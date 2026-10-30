// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"errors"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc/parser"
	"go.mondoo.com/mql/types"
)

func extractComments(c *parser.Expression) string {
	// TODO: we need to clarify how many of the comments we really want to extract.
	// For now we only grab the operand and ignore the rest
	if c == nil || c.Operand == nil {
		return ""
	}
	return c.Operand.Comments
}

func extractMsgTag(comment string) string {
	lines := strings.Split(comment, "\n")
	var msgLines strings.Builder

	var i int
	for i < len(lines) {
		if strings.HasPrefix(lines[i], "@msg ") {
			break
		}
		i++
	}
	if i == len(lines) {
		return ""
	}

	msgLines.WriteString(lines[i][5:])
	msgLines.WriteByte('\n')
	i++

	for i < len(lines) {
		line := lines[i]
		if line != "" && line[0] == '@' {
			break
		}
		msgLines.WriteString(line)
		msgLines.WriteByte('\n')
		i++
	}

	return msgLines.String()
}

func extractMql(s string) (string, error) {
	var openBrackets []byte
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			// TODO: for all of these string things we need to support proper string interpolation...
			d := s[i]
			for ; i < len(s) && s[i] != d; i++ {
			}
		case '{', '(', '[':
			openBrackets = append(openBrackets, s[i])
		case '}':
			if len(openBrackets) == 0 {
				return s[0:i], nil
			}
			last := openBrackets[len(openBrackets)-1]
			if last != '{' {
				return "", errors.New("unexpected closing bracket '" + string(s[i]) + "'")
			}
			openBrackets = openBrackets[0 : len(openBrackets)-1]
		case ')', ']':
			if len(openBrackets) == 0 {
				return "", errors.New("unexpected closing bracket '" + string(s[i]) + "'")
			}
			last := openBrackets[len(openBrackets)-1]
			if (s[i] == ')' && last != '(') || (s[i] == ']' && last != '[') {
				return "", errors.New("unexpected closing bracket '" + string(s[i]) + "'")
			}
			openBrackets = openBrackets[0 : len(openBrackets)-1]
		}
	}

	return s, nil
}

func compileAssertionMsg(msg string, c *compiler) (*llx.AssertionMessage, error) {
	template := strings.Builder{}
	var codes []string
	var i int
	max := len(msg)
	textStart := i
	for ; i < max; i++ {
		if msg[i] != '$' {
			continue
		}
		if i+1 == max || msg[i+1] != '{' {
			continue
		}

		template.WriteString(msg[textStart:i])
		template.WriteByte('$')
		template.WriteString(strconv.Itoa(len(codes)))

		// extract the code
		code, err := extractMql(msg[i+2:])
		if err != nil {
			return nil, err
		}

		i += 2 + len(code)
		if i >= max {
			return nil, errors.New("cannot extract code in @msg (message ended before '}')")
		}
		if msg[i] != '}' {
			return nil, errors.New("cannot extract code in @msg (expected '}' but got '" + string(msg[i]) + "')")
		}
		textStart = i + 1 // one past the closing '}'

		codes = append(codes, code)
	}

	template.WriteString(msg[textStart:])

	res := llx.AssertionMessage{
		Template: strings.Trim(template.String(), "\n\t "),
	}

	for i := range codes {
		code := codes[i]

		// Small helper for assertion messages:
		// At the moment, the parser can't delineate if a given `{}` call
		// is meant to be a map creation or a block call.
		//
		// When it is at the beginning of an operand it is always treated
		// as a map creation, e.g.:
		//     {a: 123, ...}             vs
		//     something { block... }
		//
		// However, in the assertion message case we know it's generally
		// not about map-creation. So we are using a workaround to more
		// easily extract values via blocks.
		//
		// This approach is extremely limited. It works with the most
		// straightforward use-case and prohibits map any type of map
		// creation in assertion messages.
		//
		// TODO: Find a more appropriate solution for this problem.
		// Identify use-cases we don't cover well with this approach
		// before changing it.

		code = strings.Trim(code, " \t\n")
		if code[0] == '{' {
			code = "_" + code
		}

		ast, err := parser.Parse(code)
		if err != nil {
			return nil, errors.New("cannot parse code block in comment: " + code)
		}

		if len(ast.Expressions) == 0 {
			return nil, errors.New("can't have empty calls to `${}` in comments")
		}
		if len(ast.Expressions) > 1 {
			return nil, errors.New("can't have more than one value in `${}`")
		}
		expression := ast.Expressions[0]

		ref, err := c.compileAndAddExpression(expression)
		if err != nil {
			return nil, errors.New("failed to compile comment: " + err.Error())
		}

		res.Refs = append(res.Refs, ref)

		c.block.Datapoints = append(c.block.Datapoints, ref)
	}

	return &res, nil
}

func compileListAssertionMsg(c *compiler, typ types.Type, allRef uint64, failedRef uint64, assertionRef uint64) error {
	// assertions
	msg := extractMsgTag(c.comment)
	if msg == "" {
		return nil
	}

	blockCompiler := c.newBlockCompiler(&variable{
		typ: typ,
		ref: failedRef,
	})

	blockCompiler.vars.add("$expected", variable{ref: allRef, typ: typ})

	assertionMsg, err := compileAssertionMsg(msg, &blockCompiler)
	if err != nil {
		return err
	}
	if assertionMsg != nil {
		if c.Result.CodeV2.Assertions == nil {
			c.Result.CodeV2.Assertions = make(map[uint64]*llx.AssertionMessage)
		}
		c.Result.CodeV2.Assertions[assertionRef+2] = assertionMsg

		args := []*llx.Primitive{
			llx.FunctionPrimitive(blockCompiler.blockRef),
		}
		for _, v := range blockCompiler.blockDeps {
			if c.isInMyBlock(v) {
				args = append(args, llx.RefPrimitiveV2(v))
			}
		}
		c.blockDeps = append(c.blockDeps, blockCompiler.blockDeps...)
		c.addChunk(&llx.Chunk{
			Call: llx.Chunk_FUNCTION,
			Id:   "${}",
			Function: &llx.Function{
				Type:    string(types.Block),
				Binding: failedRef,
				Args:    args,
			},
		})

		// since it operators on top of a block, we have to add its
		// checksum as the first entry in the list. Once the block is received,
		// all of its child entries are processed for the final result
		blockRef := c.block.TailRef(c.blockRef)
		checksum := c.Result.CodeV2.Checksums[blockRef]
		assertionMsg.Checksums = make([]string, len(assertionMsg.Refs)+1)
		assertionMsg.Checksums[0] = checksum
		c.block.Datapoints = append(c.Result.CodeV2.Blocks[0].Datapoints, blockRef)

		blocksums := blockCompiler.Result.CodeV2.Checksums
		for i := range assertionMsg.Refs {
			sum, ok := blocksums[assertionMsg.Refs[i]]
			if !ok {
				return errors.New("cannot find checksum for datapoint in @msg tag")
			}

			assertionMsg.Checksums[i+1] = sum
		}
		assertionMsg.Refs = nil
		// panic("Something about blocks decoding...")
		assertionMsg.DecodeBlock = true
	}

	return nil
}

// UpdateAssertions in a bundle and remove all intermediate assertion objects
func UpdateAssertions(bundle *llx.CodeBundle) error {
	bundle.Assertions = map[string]*llx.AssertionMessage{}
	return updateCodeAssertions(bundle, bundle.CodeV2)
}

func updateCodeAssertions(bundle *llx.CodeBundle, code *llx.CodeV2) error {
	for ref, assert := range code.Assertions {
		sum, ok := code.Checksums[ref]
		if !ok {
			return errors.New("cannot find reference for assertion")
		}

		if !assert.DecodeBlock {
			assert.Checksums = make([]string, len(assert.Refs))
			for i := range assert.Refs {
				ref := assert.Refs[i]
				assert.Checksums[i], ok = code.Checksums[ref]
				if !ok {
					return errors.New("cannot find reference to data in assertion")
				}
			}
			assert.Refs = nil
		}

		bundle.Assertions[sum] = assert
	}
	code.Assertions = nil

	return nil
}
