// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shell

import (
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"unicode"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mitchellh/go-homedir"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/mqlc/parser"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/utils/stringx"
)

// ErrNotTTY is returned when the shell is run without a terminal
var ErrNotTTY = errors.New("shell requires an interactive terminal (TTY)")

// Message types for async operations
type (
	historyLoadedMsg struct {
		history []string
	}
	queryResultMsg struct {
		code    *llx.CodeBundle
		results map[string]*llx.RawResult
		err     error
	}
	printOutputMsg struct {
		output string
	}
)

// shellModel is the main Bubble Tea model for the interactive shell
type shellModel struct {
	// Runtime and configuration
	runtime  llx.Runtime
	theme    *ShellTheme
	features mql.Features
	strict   bool
	keyMap   KeyMap

	// Input handling
	input textarea.Model

	// Completion state
	completer   *Completer
	suggestions []Suggestion
	selected    int
	showPopup   bool

	// Query state
	query           string
	isMultiline     bool
	multilineIndent int

	// History
	history      []string
	historyIdx   int
	historyDraft string
	historyPath  string

	// History search (ctrl+r)
	searchMode    bool
	searchQuery   string
	searchMatches []int // indices into history that match
	searchIdx     int   // current index into searchMatches

	// Layout
	width  int
	height int

	// State
	ready        bool
	quitting     bool
	executing    bool
	spinner      spinner.Model
	compileError string // Current compile error (if any)

	// Nyanya animation (easter egg)
	nyanya *nyanyaState
}

// newShellModel creates a new shell model
// connectedProviderIDs can be provided to filter autocomplete suggestions to only
// show resources from connected providers. If nil, all resources are shown.
func newShellModel(runtime llx.Runtime, theme *ShellTheme, features mql.Features, strict bool, initialCmd string, connectedProviderIDs []string) *shellModel {
	// Create textarea for input
	ta := textarea.New()
	ta.Placeholder = ""
	ta.CharLimit = 0 // No limit
	ta.ShowLineNumbers = false
	ta.SetHeight(1)
	ta.SetWidth(80)
	ta.Focus()

	// Set up dynamic prompt: "> " for first line, ". " for continuation
	promptWidth := len(theme.Prefix)
	ta.SetPromptFunc(promptWidth, func(lineIdx int) string {
		if lineIdx == 0 {
			return theme.Prompt.Render(theme.Prefix)
		}
		return theme.MultilinePrompt.Render(". ")
	})

	// Style the textarea
	ta.FocusedStyle.Prompt = lipgloss.NewStyle() // Prompt styling handled by SetPromptFunc
	ta.FocusedStyle.Text = theme.InputText
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()
	ta.BlurredStyle = ta.FocusedStyle

	// Create completer and set up the schema for the printer
	// If connected provider IDs are provided, use a filtered schema to only
	// show resources from connected providers in autocomplete
	schema := runtime.Schema()
	theme.PolicyPrinter.SetSchema(schema)
	completer := NewCompleter(runtime, features, strict, connectedProviderIDs)

	// Create spinner for query execution
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = theme.Spinner

	m := &shellModel{
		runtime:     runtime,
		theme:       theme,
		features:    features,
		strict:      strict,
		keyMap:      DefaultKeyMap(),
		input:       ta,
		completer:   completer,
		suggestions: nil,
		selected:    0,
		showPopup:   false,
		history:     []string{},
		historyIdx:  -1,
		width:       80,
		height:      24,
		spinner:     sp,
	}

	// Handle initial command
	if initialCmd != "" {
		m.input.SetValue(initialCmd)
	}

	return m
}

// Init implements tea.Model
func (m *shellModel) Init() tea.Cmd {
	return tea.Batch(
		textarea.Blink,
		tea.EnableBracketedPaste,
		m.loadHistory(),
		// Print welcome message
		tea.Println(m.theme.Welcome),
	)
}

// loadHistory loads command history from disk
func (m *shellModel) loadHistory() tea.Cmd {
	return func() tea.Msg {
		homeDir, err := homedir.Dir()
		if err != nil {
			log.Warn().Msg("failed to load history")
			return historyLoadedMsg{history: []string{}}
		}

		historyPath := path.Join(homeDir, ".mondoo_history")
		rawHistory, err := os.ReadFile(historyPath)
		if err != nil {
			return historyLoadedMsg{history: []string{}}
		}

		history := strings.Split(string(rawHistory), "\n")
		// Filter empty lines
		filtered := make([]string, 0, len(history))
		for _, h := range history {
			if h != "" {
				filtered = append(filtered, h)
			}
		}

		return historyLoadedMsg{history: filtered}
	}
}

// saveHistory saves command history to disk
func (m *shellModel) saveHistory() {
	if m.historyPath == "" {
		homeDir, _ := homedir.Dir()
		m.historyPath = path.Join(homeDir, ".mondoo_history")
	}

	rawHistory := strings.Join(m.history, "\n")
	if err := os.WriteFile(m.historyPath, []byte(rawHistory), 0o640); err != nil {
		log.Error().Err(err).Msg("failed to save history")
	}
}

// Update implements tea.Model
func (m *shellModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Update textarea width (leave space for prompt)
		promptLen := len(m.theme.Prefix)
		inputWidth := max(msg.Width-promptLen-2, 20)
		m.input.SetWidth(inputWidth)
		// Recalculate height in case line wrapping changed
		m.updateInputHeight()
		m.ready = true
		return m, nil

	case historyLoadedMsg:
		m.history = msg.history
		m.historyIdx = len(m.history)
		homeDir, _ := homedir.Dir()
		m.historyPath = path.Join(homeDir, ".mondoo_history")
		return m, nil

	case queryResultMsg:
		// Query finished executing
		m.executing = false
		// Resume log output, flushing any buffered debug logs
		if bw, ok := logger.LogOutputWriter.(*logger.BufferedWriter); ok {
			bw.Resume()
		}
		// Print results directly to terminal (outside of Bubble Tea's view)
		if msg.err != nil {
			output := m.theme.ErrorText("failed to compile: " + msg.err.Error())
			if msg.code != nil && msg.code.Suggestions != nil {
				output += "\n" + m.formatSuggestions(msg.code.Suggestions)
			}
			return m, tea.Println(output)
		}
		output := m.formatResults(msg.code, msg.results)
		if notices := m.deprecationNotices(msg.code); notices != "" {
			output = notices + "\n" + output
		}
		return m, tea.Println(output)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case nyanyaTickMsg:
		// Advance the nyanya animation
		if m.nyanya != nil {
			m.nyanya.currentFrame++
			if m.nyanya.currentFrame >= len(m.nyanya.frames) {
				m.nyanya.currentFrame = 0
				m.nyanya.loopCount++
				if m.nyanya.loopCount >= m.nyanya.maxLoops {
					// Animation complete
					m.nyanya = nil
					return m, nil
				}
			}
			return m, nyanyaTick()
		}
		return m, nil

	case printOutputMsg:
		// Print output directly to terminal
		return m, tea.Println(msg.output)

	case tea.KeyMsg:
		return m.handleKeyMsg(msg)
	}

	return m, tea.Batch(cmds...)
}

// handleKeyMsg processes keyboard input
func (m *shellModel) handleKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle nyanya animation - any key exits
	if m.nyanya != nil {
		m.nyanya = nil
		return m, nil
	}

	// Handle history search mode (ctrl+r)
	if m.searchMode {
		return m.handleSearchKey(msg)
	}

	// Handle pasted content - let textarea handle it but adjust height after
	if msg.Paste {
		m.showPopup = false
		m.suggestions = nil
		// Let textarea handle the paste
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		m.updateInputHeight()
		m.updateCompletions()
		return m, cmd
	}

	// Handle completion popup if visible (but not during paste)
	if m.showPopup && len(m.suggestions) > 0 {
		switch msg.String() {
		case "down", "tab":
			m.selected = (m.selected + 1) % len(m.suggestions)
			return m, nil
		case "up", "shift+tab":
			m.selected--
			if m.selected < 0 {
				m.selected = len(m.suggestions) - 1
			}
			return m, nil
		case "enter":
			// Accept the selected completion
			return m.acceptCompletion()
		case "esc":
			m.showPopup = false
			m.suggestions = nil
			return m, nil
		}
	}

	// DEBUG: see key name (uncomment to debug)
	// return m, tea.Println(fmt.Sprintf("Key: [%s] Paste: %v Runes: %d", msg.String(), msg.Paste, len(msg.Runes)))

	switch msg.String() {
	case "ctrl+left":
		m.wordLeft()
		return m, nil
	case "ctrl+right":
		m.wordRight()
		return m, nil

	case "ctrl+d":
		m.quitting = true
		return m, tea.Quit

	case "ctrl+c":
		// If there's any input or we're in multiline mode, cancel it
		if m.input.Value() != "" || m.isMultiline {
			m.isMultiline = false
			m.query = ""
			m.input.SetValue("")
			m.input.SetHeight(1)
			m.showPopup = false
			m.suggestions = nil
			// Print ^C to show the interrupt
			return m, tea.Println("^C")
		}
		// No input - quit the shell
		m.quitting = true
		return m, tea.Sequence(
			tea.Println("^C"),
			tea.Quit,
		)

	case "ctrl+l":
		// Clear screen using ANSI escape codes
		return m, tea.Println("\033[2J\033[H")

	case "ctrl+o":
		// Show asset information
		return m, m.showAssetInfo()

	case "?":
		// Show keybindings help (only when input is empty to avoid interfering with queries)
		if m.input.Value() == "" {
			helpText := m.theme.SecondaryText("Keyboard Shortcuts:") + m.keyMap.FormatFullHelp()
			return m, tea.Println(helpText)
		}

	case "ctrl+r":
		// Enter history search mode
		if len(m.history) > 0 {
			m.searchMode = true
			m.searchQuery = ""
			m.searchMatches = nil
			m.searchIdx = 0
			// Save current input as draft
			m.historyDraft = m.input.Value()
		}
		return m, nil

	case "ctrl+j":
		// Insert a newline for manual multiline input
		m.showPopup = false
		m.suggestions = nil
		m.input.InsertString("\n")
		m.updateInputHeight()
		return m, nil

	case "up":
		if len(m.history) == 0 {
			return m, nil
		}
		m.historyIdx--
		if m.historyIdx >= 0 && m.historyIdx <= len(m.history)-1 {
			m.input.SetValue(m.history[m.historyIdx])
		} else if m.historyIdx >= len(m.history) {
			m.historyIdx = len(m.history) - 1
			m.input.SetValue(m.history[m.historyIdx])
		} else {
			m.historyIdx = -1
			m.input.SetValue("")
		}
		return m, nil

	case "down":
		if len(m.history) == 0 {
			return m, nil
		}
		m.historyIdx++
		if m.historyIdx >= 0 && m.historyIdx <= len(m.history)-1 {
			m.input.SetValue(m.history[m.historyIdx])
		} else if m.historyIdx >= len(m.history) {
			m.historyIdx = len(m.history)
			m.input.SetValue("")
		} else {
			m.historyIdx = 0
			m.input.SetValue(m.history[m.historyIdx])
		}
		return m, nil

	case "enter":
		return m.handleSubmit()
	}

	// Let textarea handle all other keys
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.updateInputHeight()
	m.updateCompletions()
	return m, cmd
}

// formatInputWithPrompts formats input with proper prompts and syntax highlighting for each line
func (m *shellModel) formatInputWithPrompts(input string) string {
	lines := strings.Split(input, "\n")

	var result strings.Builder
	for i, line := range lines {
		if i == 0 {
			result.WriteString(m.theme.Prompt.Render(m.theme.Prefix))
		} else {
			result.WriteString("\n")
			result.WriteString(m.theme.MultilinePrompt.Render(". "))
		}
		// Apply syntax highlighting to the code
		result.WriteString(highlightMQL(line))
	}
	return result.String()
}

// handleSubmit processes the enter key
func (m *shellModel) handleSubmit() (tea.Model, tea.Cmd) {
	input := strings.TrimSpace(m.input.Value())

	// Handle empty input
	if input == "" && !m.isMultiline {
		return m, nil
	}

	// Echo the prompt and input so it stays in terminal history
	echoInput := m.formatInputWithPrompts(input)

	// Check for built-in commands (only when not in multiline mode)
	if !m.isMultiline {
		switch input {
		case "exit", "quit":
			m.quitting = true
			return m, tea.Sequence(
				tea.Println(echoInput),
				tea.Quit,
			)
		case "clear":
			m.input.SetValue("")
			// Clear screen using ANSI escape codes
			return m, tea.Println("\033[2J\033[H")
		case "help":
			output := m.listResources("")
			m.input.SetValue("")
			m.addToHistory(input)
			return m, tea.Sequence(
				tea.Println(echoInput),
				tea.Println(output),
			)
		case "nyanya":
			m.input.SetValue("")
			// Initialize and start the nyancat animation
			m.nyanya = initNyanya()
			if m.nyanya == nil {
				return m, tea.Println(m.theme.ErrorText("Failed to initialize nyanya animation"))
			}
			return m, tea.Batch(
				tea.Println(echoInput),
				nyanyaTick(),
			)
		}

		// Check for "help <resource>"
		if after, ok := strings.CutPrefix(input, "help "); ok {
			resource := after
			output := m.listResources(resource)
			m.input.SetValue("")
			m.addToHistory(input)
			return m, tea.Sequence(
				tea.Println(echoInput),
				tea.Println(output),
			)
		}
	}

	// Execute as MQL query
	return m.executeQuery(input)
}

// executeQuery compiles and runs an MQL query
func (m *shellModel) executeQuery(input string) (tea.Model, tea.Cmd) {
	// Echo the current line input with proper prompts
	echoInput := m.formatInputWithPrompts(input)

	// Accumulate query for multiline
	m.query += " " + input

	// Try to compile
	code, err := mqlc.Compile(m.query, nil, m.compilerConfig())
	if err != nil {
		if e, ok := err.(*parser.ErrIncomplete); ok {
			// Incomplete query - enter multiline mode
			m.isMultiline = true
			m.multilineIndent = e.Indent
			m.input.SetValue("")
			m.updatePrompt()
			// Echo the line for multiline continuation
			return m, tea.Println(echoInput)
		}
	}

	// Query is complete (or has error) - execute it
	cleanCommand := m.query
	if code != nil && code.Source != "" {
		cleanCommand = code.Source
	}

	m.addToHistory(strings.TrimSpace(cleanCommand))

	// Clear input and reset state
	m.input.SetValue("")
	m.input.SetHeight(1)
	m.isMultiline = false
	m.executing = true

	// Pause log output to prevent debug logs from interleaving with the spinner
	if bw, ok := logger.LogOutputWriter.(*logger.BufferedWriter); ok {
		bw.Pause()
	}

	// Execute the query
	queryToRun := m.query
	m.query = ""

	// Echo the input, start spinner, then execute and return results
	return m, tea.Batch(
		tea.Println(echoInput),
		m.spinner.Tick,
		func() tea.Msg {
			code, err := mqlc.Compile(queryToRun, nil, m.compilerConfig())
			if err != nil {
				return queryResultMsg{code: code, err: err}
			}

			results, err := exec.ExecuteCode(m.runtime, code, nil, m.features)
			return queryResultMsg{code: code, results: results, err: err}
		},
	)
}

// updatePrompt updates the input prompt based on multiline state
func (m *shellModel) updatePrompt() {
	// The prompt is handled by SetPromptFunc in newShellModel
	// This function is kept for compatibility but doesn't need to do anything
}

// addToHistory adds a command to history
func (m *shellModel) addToHistory(cmd string) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return
	}
	// Don't add duplicates
	if len(m.history) > 0 && m.history[len(m.history)-1] == cmd {
		return
	}
	m.history = append(m.history, cmd)
	m.historyIdx = len(m.history)
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

// wordLeft moves the cursor to the beginning of the previous word,
// skipping over any non-word characters (punctuation, whitespace).
func (m *shellModel) wordLeft() {
	runes := []rune(m.input.Value())
	pos := m.input.LineInfo().CharOffset
	// Skip non-word characters
	for pos > 0 && !isWordRune(runes[pos-1]) {
		pos--
	}
	// Skip word characters
	for pos > 0 && isWordRune(runes[pos-1]) {
		pos--
	}
	m.input.SetCursor(pos)
}

// wordRight moves the cursor to the beginning of the next word,
// skipping over any non-word characters (punctuation, whitespace).
func (m *shellModel) wordRight() {
	runes := []rune(m.input.Value())
	n := len(runes)
	pos := m.input.LineInfo().CharOffset
	// Skip word characters
	for pos < n && isWordRune(runes[pos]) {
		pos++
	}
	// Skip non-word characters
	for pos < n && !isWordRune(runes[pos]) {
		pos++
	}
	m.input.SetCursor(pos)
}

// calculateInputHeight returns the height needed for the textarea based on content
func (m *shellModel) calculateInputHeight() int {
	lines := strings.Count(m.input.Value(), "\n") + 1
	// Add extra line for cursor when at end of line with newline
	if strings.HasSuffix(m.input.Value(), "\n") {
		lines++
	}
	if lines < 1 {
		lines = 1
	}
	return lines
}

// updateInputHeight adjusts textarea height to fit content
func (m *shellModel) updateInputHeight() {
	height := m.calculateInputHeight()
	if height != m.input.Height() {
		m.input.SetHeight(height)
	}
}

// handleSearchKey processes key input during history search mode
func (m *shellModel) handleSearchKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+r":
		// Find next match (go backwards in history)
		if len(m.searchMatches) > 0 {
			m.searchIdx++
			if m.searchIdx >= len(m.searchMatches) {
				m.searchIdx = 0 // wrap around
			}
			m.applySearchMatch()
		}
		return m, nil

	case "ctrl+c", "esc":
		// Cancel search, restore original input
		m.searchMode = false
		m.input.SetValue(m.historyDraft)
		m.updateInputHeight()
		return m, nil

	case "enter":
		// Accept current match and exit search mode
		m.searchMode = false
		// Keep the current input value (already set by search)
		return m, nil

	case "backspace":
		// Remove last character from search query
		if len(m.searchQuery) > 0 {
			m.searchQuery = m.searchQuery[:len(m.searchQuery)-1]
			m.updateSearchMatches()
		}
		return m, nil

	case "ctrl+g":
		// Abort search (like in emacs)
		m.searchMode = false
		m.input.SetValue(m.historyDraft)
		m.updateInputHeight()
		return m, nil

	default:
		// Add typed characters to search query
		if len(msg.Runes) > 0 {
			for _, r := range msg.Runes {
				m.searchQuery += string(r)
			}
			m.updateSearchMatches()
		}
		return m, nil
	}
}

// updateSearchMatches finds all history entries matching the search query
func (m *shellModel) updateSearchMatches() {
	m.searchMatches = nil
	m.searchIdx = 0

	if m.searchQuery == "" {
		m.input.SetValue("")
		m.updateInputHeight()
		return
	}

	query := strings.ToLower(m.searchQuery)

	// Search backwards through history (most recent first)
	for i, v := range slices.Backward(m.history) {
		if strings.Contains(strings.ToLower(v), query) {
			m.searchMatches = append(m.searchMatches, i)
		}
	}

	m.applySearchMatch()
}

// applySearchMatch applies the current search match to the input
func (m *shellModel) applySearchMatch() {
	if len(m.searchMatches) == 0 {
		m.input.SetValue("")
		m.updateInputHeight()
		return
	}

	idx := m.searchMatches[m.searchIdx]
	m.input.SetValue(m.history[idx])
	m.historyIdx = idx
	m.updateInputHeight()
	m.input.CursorStart()
}

// isBuiltinCommand checks if the input is a built-in shell command
func isBuiltinCommand(input string) bool {
	trimmed := strings.TrimSpace(input)
	switch {
	case trimmed == "exit", trimmed == "quit", trimmed == "clear", trimmed == "help", trimmed == "nyanya":
		return true
	case strings.HasPrefix(trimmed, "help "):
		return true
	}
	return false
}

// updateCompletions fetches new completions based on current input
func (m *shellModel) updateCompletions() {
	input := m.input.Value()
	if input == "" {
		m.showPopup = false
		m.suggestions = nil
		m.compileError = ""
		return
	}

	// Get completions
	suggestions := m.completer.Complete(input)
	if len(suggestions) > 0 {
		m.suggestions = suggestions
		m.selected = 0
		m.showPopup = true
	} else {
		m.showPopup = false
		m.suggestions = nil
	}

	// Skip compile error checking for built-in shell commands
	if isBuiltinCommand(input) {
		m.compileError = ""
		return
	}

	// Check for compile errors (for inline feedback)
	fullQuery := m.query + " " + input
	_, err := mqlc.Compile(fullQuery, nil, m.compilerConfig())
	if err != nil {
		// Ignore incomplete errors - those are expected for multi-line
		if _, ok := err.(*parser.ErrIncomplete); !ok {
			m.compileError = err.Error()
		} else {
			m.compileError = ""
		}
	} else {
		m.compileError = ""
	}
}

// acceptCompletion inserts the selected completion
func (m *shellModel) acceptCompletion() (tea.Model, tea.Cmd) {
	if m.selected >= 0 && m.selected < len(m.suggestions) {
		suggestion := m.suggestions[m.selected]

		// Get current input and find the word to replace
		input := m.input.Value()

		// Find the start of the current word (after last separator)
		lastDot := strings.LastIndex(input, ".")
		lastSpace := strings.LastIndex(input, " ")
		wordStart := max(lastSpace, lastDot)

		var newValue string
		if wordStart >= 0 {
			newValue = input[:wordStart+1] + suggestion.Text
		} else {
			newValue = suggestion.Text
		}

		m.input.SetValue(newValue)
	}

	m.showPopup = false
	m.suggestions = nil

	// Recompile the query to update error display after completion
	m.recompileForErrors()

	return m, nil
}

// recompileForErrors recompiles the current query to update the error display
// without triggering new completion suggestions
func (m *shellModel) recompileForErrors() {
	input := m.input.Value()
	if input == "" {
		m.compileError = ""
		return
	}

	// Skip compile error checking for built-in shell commands
	if isBuiltinCommand(input) {
		m.compileError = ""
		return
	}

	// Check for compile errors
	fullQuery := m.query + " " + input
	_, err := mqlc.Compile(fullQuery, nil, m.compilerConfig())
	if err != nil {
		// Ignore incomplete errors - those are expected for multi-line
		if _, ok := err.(*parser.ErrIncomplete); !ok {
			m.compileError = err.Error()
		} else {
			m.compileError = ""
		}
	} else {
		m.compileError = ""
	}
}

// View implements tea.Model
func (m *shellModel) View() string {
	if !m.ready {
		return "Loading..."
	}

	// Render nyanya animation if active (full screen modal)
	if m.nyanya != nil {
		return renderNyanya(m.nyanya, m.width, m.height)
	}

	var b strings.Builder

	// Show spinner when executing, otherwise show input
	if m.executing {
		b.WriteString(m.spinner.View())
		b.WriteString(" Executing query...")
	} else if m.searchMode {
		// Show search interface
		b.WriteString(m.renderSearchView())
	} else {
		// Render textarea input
		b.WriteString(m.input.View())

		// Completion popup
		if m.showPopup && len(m.suggestions) > 0 {
			b.WriteString("\n")
			b.WriteString(m.renderCompletionPopup())
		}

		// Show compile error if any
		if m.compileError != "" && !m.showPopup {
			b.WriteString("\n")
			// Truncate long error messages
			errMsg := m.compileError
			maxLen := m.width - 4
			if maxLen > 0 && len(errMsg) > maxLen {
				errMsg = errMsg[:maxLen-3] + "..."
			}
			b.WriteString(m.theme.Error.Render("⚠ " + errMsg))
		}
	}

	// Help bar at the bottom (with empty line separator)
	b.WriteString("\n\n")
	b.WriteString(m.renderHelpBar())

	return b.String()
}

// showAssetInfo executes a query to display asset information
func (m *shellModel) showAssetInfo() tea.Cmd {
	return func() tea.Msg {
		// Query for asset information using proper MQL syntax
		query := "asset.name asset.platform asset.version"
		code, err := mqlc.Compile(query, nil, m.compilerConfig())
		if err != nil {
			return printOutputMsg{output: m.theme.ErrorText("Failed to get asset info: " + err.Error())}
		}

		results, err := exec.ExecuteCode(m.runtime, code, nil, m.features)
		if err != nil {
			return printOutputMsg{output: m.theme.ErrorText("Failed to get asset info: " + err.Error())}
		}

		// Format output nicely
		var lines []string
		lines = append(lines, m.theme.SecondaryText("Asset Information"))

		// Extract values from results in order
		for _, entry := range code.CodeV2.Entrypoints() {
			checksum := code.CodeV2.Checksums[entry]
			if result, ok := results[checksum]; ok && result.Data != nil {
				label := code.Labels.Labels[checksum]
				value := result.Data.Value
				lines = append(lines, fmt.Sprintf("  %s: %v", m.theme.HelpKey.Render(label), value))
			}
		}

		return printOutputMsg{output: strings.Join(lines, "\n")}
	}
}

// renderSearchView renders the history search interface
func (m *shellModel) renderSearchView() string {
	var b strings.Builder

	// Show the search prompt
	searchPrompt := m.theme.Secondary.Render("(reverse-i-search)`") +
		m.theme.HelpKey.Render(m.searchQuery) +
		m.theme.Secondary.Render("': ")

	b.WriteString(searchPrompt)

	// Show current match or empty
	if len(m.searchMatches) > 0 {
		// Show the matched command (first line only for preview)
		match := m.history[m.searchMatches[m.searchIdx]]
		lines := strings.Split(match, "\n")
		preview := lines[0]
		if len(lines) > 1 {
			preview += m.theme.Disabled.Render(" ...")
		}
		b.WriteString(preview)
	} else if m.searchQuery != "" {
		b.WriteString(m.theme.Disabled.Render("(no match)"))
	}

	// Show match count
	if len(m.searchMatches) > 0 {
		b.WriteString("\n")
		b.WriteString(m.theme.HelpText.Render(fmt.Sprintf("  [%d/%d matches]", m.searchIdx+1, len(m.searchMatches))))
	}

	return b.String()
}

// renderHelpBar renders the help bar with available key bindings
func (m *shellModel) renderHelpBar() string {
	var items []string

	if m.searchMode {
		items = []string{
			m.theme.HelpKey.Render("ctrl+r") + m.theme.HelpText.Render(" next"),
			m.theme.HelpKey.Render("enter") + m.theme.HelpText.Render(" select"),
			m.theme.HelpKey.Render("esc") + m.theme.HelpText.Render(" cancel"),
		}
	} else if m.showPopup {
		items = []string{
			m.theme.HelpKey.Render("↑↓") + m.theme.HelpText.Render(" navigate"),
			m.theme.HelpKey.Render("tab") + m.theme.HelpText.Render(" select"),
			m.theme.HelpKey.Render("esc") + m.theme.HelpText.Render(" dismiss"),
		}
	} else if m.executing {
		items = []string{
			m.theme.HelpText.Render("query running..."),
		}
	} else {
		items = []string{
			m.theme.HelpKey.Render("enter") + m.theme.HelpText.Render(" run"),
			m.theme.HelpKey.Render("ctrl+r") + m.theme.HelpText.Render(" search"),
			m.theme.HelpKey.Render("ctrl+d") + m.theme.HelpText.Render(" exit"),
			m.theme.HelpKey.Render("?") + m.theme.HelpText.Render(" help"),
		}
	}

	return strings.Join(items, m.theme.HelpText.Render(" • "))
}

// renderCompletionPopup renders the completion suggestions
func (m *shellModel) renderCompletionPopup() string {
	if len(m.suggestions) == 0 {
		return ""
	}

	maxItems := min(len(m.suggestions), 10)

	// Calculate scroll offset
	startIdx := 0
	if m.selected >= maxItems {
		startIdx = m.selected - maxItems + 1
	}

	// Calculate available width and column sizes
	availableWidth := m.width
	if availableWidth < 40 {
		availableWidth = 80 // fallback
	}

	// Reserve space for: padding (4), separator (3), description (min 20)
	minDescWidth := 20
	maxNameWidth := max(
		// Cap name column width
		min(

			availableWidth-minDescWidth-7, 40), 15)

	// Find the longest name in visible items (for alignment)
	nameWidth := 0
	for i := startIdx; i < startIdx+maxItems && i < len(m.suggestions); i++ {
		nameLen := len(m.suggestions[i].Text)
		if nameLen > nameWidth {
			nameWidth = nameLen
		}
	}
	// Clamp to maxNameWidth
	if nameWidth > maxNameWidth {
		nameWidth = maxNameWidth
	}
	if nameWidth < 10 {
		nameWidth = 10
	}

	// Calculate description width
	descWidth := min(max(availableWidth-nameWidth-7, minDescWidth), 50)

	var rows []string
	for i := startIdx; i < startIdx+maxItems && i < len(m.suggestions); i++ {
		s := m.suggestions[i]

		var suggStyle, descStyle lipgloss.Style
		if i == m.selected {
			suggStyle = m.theme.SuggestionSelected
			descStyle = m.theme.DescriptionSelected
		} else {
			suggStyle = m.theme.SuggestionNormal
			descStyle = m.theme.DescriptionNormal
		}

		// Truncate name if needed
		name := s.Text
		if len(name) > nameWidth {
			name = name[:nameWidth-1] + "…"
		}

		// Truncate description if needed
		desc := s.Description
		if len(desc) > descWidth {
			desc = desc[:descWidth-1] + "…"
		}

		// Format with proper alignment
		nameFormatted := fmt.Sprintf("%-*s", nameWidth, name)
		descFormatted := fmt.Sprintf("%-*s", descWidth, desc)

		row := suggStyle.Render(nameFormatted) + " " + descStyle.Render(descFormatted)
		rows = append(rows, row)
	}

	// Add scroll indicator if needed
	if len(m.suggestions) > maxItems {
		indicator := fmt.Sprintf(" ↑↓ %d/%d", m.selected+1, len(m.suggestions))
		rows = append(rows, m.theme.ScrollIndicator.Render(indicator))
	}

	return strings.Join(rows, "\n")
}

// formatResults formats query results for display
func (m *shellModel) formatResults(code *llx.CodeBundle, results map[string]*llx.RawResult) string {
	result := m.theme.PolicyPrinter.Results(code, results)

	// Apply max lines limit (1024 by default)
	result = stringx.MaxLines(1024, result)

	return result
}

// formatSuggestions formats compiler suggestions for display
func (m *shellModel) formatSuggestions(suggestions []*llx.Documentation) string {
	var b strings.Builder
	b.WriteString(m.theme.SecondaryText("\nsuggestions:\n"))
	for _, s := range suggestions {
		b.WriteString("- " + s.Field + ": " + s.Title + "\n")
	}
	return b.String()
}

// listResources lists available resources
func (m *shellModel) listResources(filter string) string {
	allResources := m.runtime.Schema().AllResources()

	var keys []string
	for k := range allResources {
		if filter == "" || strings.HasPrefix(k, filter) {
			keys = append(keys, k)
		}
	}

	if len(keys) == 0 {
		return "No resources found"
	}

	// Sort keys
	sortedKeys := make([]string, len(keys))
	copy(sortedKeys, keys)
	for i := range sortedKeys {
		for j := i + 1; j < len(sortedKeys); j++ {
			if sortedKeys[i] > sortedKeys[j] {
				sortedKeys[i], sortedKeys[j] = sortedKeys[j], sortedKeys[i]
			}
		}
	}

	var b strings.Builder
	for _, k := range sortedKeys {
		resource := allResources[k]
		b.WriteString(m.theme.SecondaryText(resource.Name))
		if label := resources.MaturityLabel(resource.Maturity); label != "" {
			b.WriteString(" [" + label + "]")
		}
		b.WriteString(": ")
		b.WriteString(resource.Title)
		b.WriteString("\n")

		// If filtering to a specific resource, show its fields
		if filter != "" && k == filter {
			for _, field := range resource.Fields {
				if field.IsPrivate {
					continue
				}
				b.WriteString("  ")
				b.WriteString(m.theme.SecondaryText(field.Name))
				if label := resources.MaturityLabel(resources.EffectiveFieldMaturity(resource, field)); label != "" {
					b.WriteString(" [" + label + "]")
				}
				b.WriteString(": ")
				b.WriteString(field.Title)
				b.WriteString("\n")
			}
		}
	}

	return b.String()
}

// compilerConfig is the shell's compile settings, including the strict-mode
// default resolved from config. Queries typed at the shell carry no content of
// their own, so the config default is all there is.
func (m *shellModel) compilerConfig() mqlc.CompilerConfig {
	conf := mqlc.NewConfigFrom(m.runtime, m.features)
	conf.Strict = m.strict
	// Interactive recompiles run on every keystroke, so keep non-fatal
	// advisories like the standalone where warning out of the terminal.
	conf.EditorMode = true
	return conf
}

// deprecationNotices renders what the bundle recorded about deprecated names it
// reads (ADR 040). The compiler only records - it runs on every keystroke
// behind autocomplete, so a message printed from there lands in the middle of
// the line being typed - and this is the moment a user is actually reading
// output.
//
// Spellings are relative to the root this session connected to, so the notice
// tells them what to type here rather than where the field lives in the schema.
func (m *shellModel) deprecationNotices(code *llx.CodeBundle) string {
	notices := mqlc.DeprecationNotices(code, m.runtime.Schema())
	if len(notices) == 0 {
		return ""
	}
	var out strings.Builder
	for _, n := range notices {
		out.WriteString(m.theme.Secondary.Render("deprecated: " + n))
		out.WriteString("\n")
	}
	return strings.TrimRight(out.String(), "\n")
}
