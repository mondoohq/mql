// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"go.mondoo.com/mql/providers-sdk/v1/mqlr/lrcore"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

func init() {
	markdownCmd.Flags().String("pack-name", "", "name of the resource pack")
	markdownCmd.Flags().String("description", "", "description of the resource pack")
	markdownCmd.Flags().StringP("output", "o", ".build", "local path to the resource pack in the docs repo")
	rootCmd.AddCommand(markdownCmd)
}

const frontMatterTemplate = `---
title: {{ .PackName }} Resource Pack - MQL Resources
id: {{ .ID }}.pack
sidebar_label: {{ .PackName }} Resource Pack
displayed_sidebar: MQL
description: {{ .Description }}
---
`

var markdownCmd = &cobra.Command{
	Use:   "markdown",
	Short: "generates markdown files",
	Long:  `parse an LR file and generates a markdown file`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		raw, err := os.ReadFile(args[0])
		if err != nil {
			log.Error().Msg(err.Error())
			return
		}

		outputDir, err := cmd.Flags().GetString("output")
		if err != nil {
			log.Fatal().Err(err).Msg("no output directory provided")
		}

		res, err := lrcore.Parse(string(raw))
		if err != nil {
			log.Error().Msg(err.Error())
			return
		}

		schema, err := lrcore.Schema(res)
		if err != nil {
			log.Error().Err(err).Msg("failed to generate schema")
		}

		// to ensure we generate the same markdown, we sort the resources first
		sort.SliceStable(res.Resources, func(i, j int) bool {
			return res.Resources[i].ID < res.Resources[j].ID
		})

		// generate resource map for hyperlink generation and table of content
		resourceHrefMap := map[string]bool{}
		for i := range res.Resources {
			resource := res.Resources[i]
			resourceHrefMap[resource.ID] = true
		}

		// render all resources incl. fields and examples
		r := &lrSchemaRenderer{
			resourceHrefMap: resourceHrefMap,
		}

		// render readme
		packName, _ := cmd.Flags().GetString("pack-name")
		err = os.MkdirAll(outputDir, 0o755)
		if err != nil {
			log.Fatal().Err(err).Msg("could not create directory: " + outputDir)
		}
		description, _ := cmd.Flags().GetString("description")
		err = os.MkdirAll(outputDir, 0o755)
		if err != nil {
			log.Fatal().Err(err).Msg("could not create directory: " + outputDir)
		}
		err = os.WriteFile(filepath.Join(outputDir, "README.md"), []byte(r.renderToc(packName, description, res.Resources, schema)), 0o600)
		if err != nil {
			log.Fatal().Err(err).Msg("could not write file")
		}

		for i := range res.Resources {
			resource := res.Resources[i]
			err = os.WriteFile(filepath.Join(outputDir, strings.ToLower(resource.ID+".md")), []byte(r.renderResourcePage(resource, schema)), 0o600)
			if err != nil {
				log.Fatal().Err(err).Msg("could not write file")
			}
		}
	},
}

var reNonID = regexp.MustCompile(`[^A-Za-z0-9-]+`)

type lrSchemaRenderer struct {
	resourceHrefMap map[string]bool
}

func toID(s string) string {
	s = reNonID.ReplaceAllString(s, ".")
	s = strings.ToLower(s)
	return strings.Trim(s, ".")
}

func (l *lrSchemaRenderer) renderToc(packName string, description string, resources []*lrcore.Resource, schema *resources.Schema) string {
	builder := &strings.Builder{}

	// render front matter
	tpl, _ := template.New("frontmatter").Parse(frontMatterTemplate)
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	err := tpl.Execute(writer, struct {
		PackName    string
		Description string
		ID          string
	}{
		PackName:    packName,
		Description: description,
		ID:          toID(packName),
	})
	if err != nil {
		panic(err)
	}
	writer.Flush()
	builder.WriteString(buf.String())
	builder.WriteString("\n")

	// render content
	builder.WriteString("# " + packName + " MQL Resource Pack Reference\n\n")
	builder.WriteString(description + "\n\n")
	builder.WriteString("Resources included in this pack:\n\n")
	rows := [][]string{}

	for i := range resources {
		resource := resources[i]
		rows = append(rows, []string{"[" + resource.ID + "](" + mdRef(resource.ID) + ")", sanitizeMarkdownText(schema.Resources[resource.ID].Title)})
	}

	table := tablewriter.NewTable(builder,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Borders: tw.Border{Left: tw.On, Top: tw.Off, Right: tw.On, Bottom: tw.Off},
			Symbols: tw.NewSymbolCustom("mql").
				WithCenter("|").
				WithMidLeft("|").
				WithMidRight("|"),
		})),
		tablewriter.WithConfig(tablewriter.Config{
			Header: tw.CellConfig{
				Alignment: tw.CellAlignment{Global: tw.AlignLeft}, // Left-align rows
			},
			Row: tw.CellConfig{
				Alignment: tw.CellAlignment{Global: tw.AlignLeft}, // Left-align rows
				Formatting: tw.CellFormatting{
					AutoWrap: tw.WrapNone,
				},
			},
			Footer: tw.CellConfig{
				Alignment: tw.CellAlignment{Global: tw.AlignRight},
			},
		}),
	)
	table.Header([]string{"ID", "Description"})
	err = table.Bulk(rows)
	if err != nil {
		panic(err)
	}
	err = table.Render()
	if err != nil {
		panic(err)
	}
	builder.WriteString("\n")

	return builder.String()
}

// trimColon removes any : from the string since colons are not allowed in markdown front matter
func trimColon(s string) string {
	return strings.ReplaceAll(s, ":", "")
}

func (l *lrSchemaRenderer) renderResourcePage(resource *lrcore.Resource, schema *resources.Schema) string {
	builder := &strings.Builder{}

	builder.WriteString("---\n")
	builder.WriteString("title: " + resource.ID + "\n")
	builder.WriteString("id: " + resource.ID + "\n")
	builder.WriteString("sidebar_label: " + resource.ID + "\n")
	builder.WriteString("displayed_sidebar: MQL\n")

	headerDesc := sanitizeMarkdownText(schema.Resources[resource.ID].Title)
	if headerDesc != "" {
		builder.WriteString("description: " + trimColon(headerDesc) + "\n")
	}
	builder.WriteString("---\n")
	builder.WriteString("\n")

	builder.WriteString("# ")
	builder.WriteString(resource.ID)
	builder.WriteString("\n\n")

	if label := resources.MaturityLabel(schema.Resources[resource.ID].Maturity); label != "" {
		builder.WriteString("**Maturity**: " + label + "\n\n")
	}

	if schema.Resources[resource.ID].Title != "" {
		builder.WriteString("**Description**\n\n")
		builder.WriteString(sanitizeMarkdownText(schema.Resources[resource.ID].Title))
		builder.WriteString("\n\n")
	}

	inits := resource.GetInitFields()
	// generate the constructor
	if len(inits) > 0 {
		builder.WriteString("**Init**\n\n")
		for j := range inits {
			init := inits[j]

			for a := range init.Args {
				arg := init.Args[a]
				builder.WriteString(resource.ID + "(" + arg.ID + " " + renderLrType(arg.Type, l.resourceHrefMap) + ")")
				builder.WriteString("\n")
			}
		}
		builder.WriteString("\n")
	}

	if resource.ListType != nil {
		builder.WriteString("**List**\n\n")
		builder.WriteString("[]" + resource.ListType.Type.Type)
		builder.WriteString("\n\n")
	}

	basicFields := []*lrcore.BasicField{}
	comments := [][]lrcore.CommentToken{}
	for _, f := range resource.Body.Fields {
		if f.BasicField != nil {
			basicFields = append(basicFields, f.BasicField)
			comments = append(comments, f.Comments)
		}
	}
	// generate the fields markdown table
	// NOTE: list types may not have any fields
	if len(basicFields) > 0 {
		builder.WriteString("**Fields**\n\n")
		rows := [][]string{}

		resourceInfo := schema.Resources[resource.ID]
		for k := range basicFields {
			field := basicFields[k]
			row := []string{
				field.ID, renderLrType(field.Type, l.resourceHrefMap),
				strings.Join(sanitizeComments(comments[k]), ", "),
			}
			maturityLabel := ""
			if resourceInfo != nil {
				if fieldInfo, ok := resourceInfo.Fields[field.ID]; ok {
					maturityLabel = resources.MaturityLabel(resources.EffectiveFieldMaturity(resourceInfo, fieldInfo))
				}
			}
			row = append(row, maturityLabel)
			rows = append(rows, row)
		}

		table := tablewriter.NewTable(builder,
			tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
				Borders: tw.Border{Left: tw.On, Top: tw.Off, Right: tw.On, Bottom: tw.Off},
				Symbols: tw.NewSymbolCustom("mql").
					WithCenter("|").
					WithMidLeft("|").
					WithMidRight("|"),
			})),
			tablewriter.WithConfig(tablewriter.Config{
				Header: tw.CellConfig{
					Alignment: tw.CellAlignment{Global: tw.AlignLeft}, // Left-align rows
				},
				Row: tw.CellConfig{
					Alignment: tw.CellAlignment{Global: tw.AlignLeft}, // Left-align rows
					Formatting: tw.CellFormatting{
						AutoWrap: tw.WrapNone,
					},
				},
				Footer: tw.CellConfig{
					Alignment: tw.CellAlignment{Global: tw.AlignRight},
				},
			}),
		)
		table.Header([]string{"ID", "Type", "Description", "Maturity"})
		err := table.Bulk(rows)
		if err != nil {
			panic(err)
		}
		err = table.Render()
		if err != nil {
			panic(err)
		}
		builder.WriteString("\n")
	}

	return builder.String()
}

func mdRef(name string) string {
	return strings.ToLower(name) + ".md"
}

func renderLrType(t lrcore.Type, resourceHrefMap map[string]bool) string {
	switch {
	case t.SimpleType != nil:
		_, ok := resourceHrefMap[t.SimpleType.Type]
		if ok {
			return "[" + t.SimpleType.Type + "](" + mdRef(t.SimpleType.Type) + ")"
		}
		return t.SimpleType.Type
	case t.ListType != nil:
		// we need a space between [] and the link, otherwise some markdown link parsers do not render the links properly
		// related to https://github.com/facebook/docusaurus/issues/4801
		return "&#91;&#93;" + renderLrType(t.ListType.Type, resourceHrefMap)
	case t.MapType != nil:
		return "map[" + t.MapType.Key.Type + "]" + renderLrType(t.MapType.Value, resourceHrefMap)
	default:
		return "?"
	}
}

func sanitizeMarkdownText(s string) string {
	s = strings.TrimPrefix(s, "// ")
	// Unescape pre-escaped pipes so all | are uniform, then re-escape them.
	// Doing it in two passes avoids double-escaping (\\|).
	s = strings.ReplaceAll(s, `\|`, `|`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return s
}

func sanitizeComments(comments []lrcore.CommentToken) []string {
	sanitizedComments := []string{}
	for _, c := range comments {
		sanitizedComments = append(sanitizedComments, sanitizeMarkdownText(c.Text))
	}
	return sanitizedComments
}
