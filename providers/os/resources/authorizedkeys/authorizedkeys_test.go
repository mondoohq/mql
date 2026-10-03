// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package authorizedkeys

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizedKeyParser(t *testing.T) {

	content := `
# Comments allowed at start of line
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDYuKamN4JXNYmolm+A9hM+xYanupG1VgbM/k0NwPiIPUdiU82IPbP7bunsngnOatSDyCrKrhL9FV3wuHFFBX0QE9KpS8bcIcT3ySsi3wgYV95P7anb7YhliDDx2w/QB97kCnAKjGFS1yphS6px0i9B29tGVJa22ODs/hebIKUCYKC9/+fnZ+bIqte1HctDP2lDBzMa/7j8BUXSwnTDXtAuEz5eSMIpv1ZdUdaSuO8xFbB0xrBHQJKuqboLPo3NSOCg6uhopO6GucZuNLJnqVLkyEPTKH0nv/8smz/q3v1GOGz8ZS0DIpkretKZmRB1VDhNqsAiOAWUTmg56xO7VZnlEvQRtyG8qyQHjlj6SDGtvxPDY58lz5nhIV9K6L7gHrOIcbSif5ZCt0e4DrKGaYXgH+mwIh2TMC2OCU6Xr6FRVQ9fBhilqMXuFIIezShN0hZb6mUCLkLVOzBBRKuz17S2a8twsuxix7ixqJPsIF3sI88tbxrFkSGSM02dhrmyZbkMr586rktVBB4T+8A28HJr4l9jkU0uk3l3le5bMcXhEuDkJUBnwEXEXfZa8Lw4sg2VuFgw0Ah0kw0/mAorpsFahXstNgrHhy3HoPKDCw/a/sXL4+fE72I1L96Lb7HOxTrdhEGnd65W4mPlTnbGW9YDQqTfZgRlpuffqQuWWYXolw== user@example.net
from="*.sales.example.net,!pc.sales.example.net" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDYuKamN4JXNYmolm+A9hM+xYanupG1VgbM/k0NwPiIPUdiU82IPbP7bunsngnOatSDyCrKrhL9FV3wuHFFBX0QE9KpS8bcIcT3ySsi3wgYV95P7anb7YhliDDx2w/QB97kCnAKjGFS1yphS6px0i9B29tGVJa22ODs/hebIKUCYKC9/+fnZ+bIqte1HctDP2lDBzMa/7j8BUXSwnTDXtAuEz5eSMIpv1ZdUdaSuO8xFbB0xrBHQJKuqboLPo3NSOCg6uhopO6GucZuNLJnqVLkyEPTKH0nv/8smz/q3v1GOGz8ZS0DIpkretKZmRB1VDhNqsAiOAWUTmg56xO7VZnlEvQRtyG8qyQHjlj6SDGtvxPDY58lz5nhIV9K6L7gHrOIcbSif5ZCt0e4DrKGaYXgH+mwIh2TMC2OCU6Xr6FRVQ9fBhilqMXuFIIezShN0hZb6mUCLkLVOzBBRKuz17S2a8twsuxix7ixqJPsIF3sI88tbxrFkSGSM02dhrmyZbkMr586rktVBB4T+8A28HJr4l9jkU0uk3l3le5bMcXhEuDkJUBnwEXEXfZa8Lw4sg2VuFgw0Ah0kw0/mAorpsFahXstNgrHhy3HoPKDCw/a/sXL4+fE72I1L96Lb7HOxTrdhEGnd65W4mPlTnbGW9YDQqTfZgRlpuffqQuWWYXolw== john@example.net
command="dump /home",no-pty,no-port-forwarding ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDYuKamN4JXNYmolm+A9hM+xYanupG1VgbM/k0NwPiIPUdiU82IPbP7bunsngnOatSDyCrKrhL9FV3wuHFFBX0QE9KpS8bcIcT3ySsi3wgYV95P7anb7YhliDDx2w/QB97kCnAKjGFS1yphS6px0i9B29tGVJa22ODs/hebIKUCYKC9/+fnZ+bIqte1HctDP2lDBzMa/7j8BUXSwnTDXtAuEz5eSMIpv1ZdUdaSuO8xFbB0xrBHQJKuqboLPo3NSOCg6uhopO6GucZuNLJnqVLkyEPTKH0nv/8smz/q3v1GOGz8ZS0DIpkretKZmRB1VDhNqsAiOAWUTmg56xO7VZnlEvQRtyG8qyQHjlj6SDGtvxPDY58lz5nhIV9K6L7gHrOIcbSif5ZCt0e4DrKGaYXgH+mwIh2TMC2OCU6Xr6FRVQ9fBhilqMXuFIIezShN0hZb6mUCLkLVOzBBRKuz17S2a8twsuxix7ixqJPsIF3sI88tbxrFkSGSM02dhrmyZbkMr586rktVBB4T+8A28HJr4l9jkU0uk3l3le5bMcXhEuDkJUBnwEXEXfZa8Lw4sg2VuFgw0Ah0kw0/mAorpsFahXstNgrHhy3HoPKDCw/a/sXL4+fE72I1L96Lb7HOxTrdhEGnd65W4mPlTnbGW9YDQqTfZgRlpuffqQuWWYXolw== example.net
permitopen="192.0.2.1:80",permitopen="192.0.2.2:25" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDYuKamN4JXNYmolm+A9hM+xYanupG1VgbM/k0NwPiIPUdiU82IPbP7bunsngnOatSDyCrKrhL9FV3wuHFFBX0QE9KpS8bcIcT3ySsi3wgYV95P7anb7YhliDDx2w/QB97kCnAKjGFS1yphS6px0i9B29tGVJa22ODs/hebIKUCYKC9/+fnZ+bIqte1HctDP2lDBzMa/7j8BUXSwnTDXtAuEz5eSMIpv1ZdUdaSuO8xFbB0xrBHQJKuqboLPo3NSOCg6uhopO6GucZuNLJnqVLkyEPTKH0nv/8smz/q3v1GOGz8ZS0DIpkretKZmRB1VDhNqsAiOAWUTmg56xO7VZnlEvQRtyG8qyQHjlj6SDGtvxPDY58lz5nhIV9K6L7gHrOIcbSif5ZCt0e4DrKGaYXgH+mwIh2TMC2OCU6Xr6FRVQ9fBhilqMXuFIIezShN0hZb6mUCLkLVOzBBRKuz17S2a8twsuxix7ixqJPsIF3sI88tbxrFkSGSM02dhrmyZbkMr586rktVBB4T+8A28HJr4l9jkU0uk3l3le5bMcXhEuDkJUBnwEXEXfZa8Lw4sg2VuFgw0Ah0kw0/mAorpsFahXstNgrHhy3HoPKDCw/a/sXL4+fE72I1L96Lb7HOxTrdhEGnd65W4mPlTnbGW9YDQqTfZgRlpuffqQuWWYXolw==
permitlisten="localhost:8080",permitopen="localhost:22000" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDYuKamN4JXNYmolm+A9hM+xYanupG1VgbM/k0NwPiIPUdiU82IPbP7bunsngnOatSDyCrKrhL9FV3wuHFFBX0QE9KpS8bcIcT3ySsi3wgYV95P7anb7YhliDDx2w/QB97kCnAKjGFS1yphS6px0i9B29tGVJa22ODs/hebIKUCYKC9/+fnZ+bIqte1HctDP2lDBzMa/7j8BUXSwnTDXtAuEz5eSMIpv1ZdUdaSuO8xFbB0xrBHQJKuqboLPo3NSOCg6uhopO6GucZuNLJnqVLkyEPTKH0nv/8smz/q3v1GOGz8ZS0DIpkretKZmRB1VDhNqsAiOAWUTmg56xO7VZnlEvQRtyG8qyQHjlj6SDGtvxPDY58lz5nhIV9K6L7gHrOIcbSif5ZCt0e4DrKGaYXgH+mwIh2TMC2OCU6Xr6FRVQ9fBhilqMXuFIIezShN0hZb6mUCLkLVOzBBRKuz17S2a8twsuxix7ixqJPsIF3sI88tbxrFkSGSM02dhrmyZbkMr586rktVBB4T+8A28HJr4l9jkU0uk3l3le5bMcXhEuDkJUBnwEXEXfZa8Lw4sg2VuFgw0Ah0kw0/mAorpsFahXstNgrHhy3HoPKDCw/a/sXL4+fE72I1L96Lb7HOxTrdhEGnd65W4mPlTnbGW9YDQqTfZgRlpuffqQuWWYXolw==
tunnel="0",command="sh /etc/netstart tun0" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDYuKamN4JXNYmolm+A9hM+xYanupG1VgbM/k0NwPiIPUdiU82IPbP7bunsngnOatSDyCrKrhL9FV3wuHFFBX0QE9KpS8bcIcT3ySsi3wgYV95P7anb7YhliDDx2w/QB97kCnAKjGFS1yphS6px0i9B29tGVJa22ODs/hebIKUCYKC9/+fnZ+bIqte1HctDP2lDBzMa/7j8BUXSwnTDXtAuEz5eSMIpv1ZdUdaSuO8xFbB0xrBHQJKuqboLPo3NSOCg6uhopO6GucZuNLJnqVLkyEPTKH0nv/8smz/q3v1GOGz8ZS0DIpkretKZmRB1VDhNqsAiOAWUTmg56xO7VZnlEvQRtyG8qyQHjlj6SDGtvxPDY58lz5nhIV9K6L7gHrOIcbSif5ZCt0e4DrKGaYXgH+mwIh2TMC2OCU6Xr6FRVQ9fBhilqMXuFIIezShN0hZb6mUCLkLVOzBBRKuz17S2a8twsuxix7ixqJPsIF3sI88tbxrFkSGSM02dhrmyZbkMr586rktVBB4T+8A28HJr4l9jkU0uk3l3le5bMcXhEuDkJUBnwEXEXfZa8Lw4sg2VuFgw0Ah0kw0/mAorpsFahXstNgrHhy3HoPKDCw/a/sXL4+fE72I1L96Lb7HOxTrdhEGnd65W4mPlTnbGW9YDQqTfZgRlpuffqQuWWYXolw== jane@example.net
restrict,command="uptime" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDYuKamN4JXNYmolm+A9hM+xYanupG1VgbM/k0NwPiIPUdiU82IPbP7bunsngnOatSDyCrKrhL9FV3wuHFFBX0QE9KpS8bcIcT3ySsi3wgYV95P7anb7YhliDDx2w/QB97kCnAKjGFS1yphS6px0i9B29tGVJa22ODs/hebIKUCYKC9/+fnZ+bIqte1HctDP2lDBzMa/7j8BUXSwnTDXtAuEz5eSMIpv1ZdUdaSuO8xFbB0xrBHQJKuqboLPo3NSOCg6uhopO6GucZuNLJnqVLkyEPTKH0nv/8smz/q3v1GOGz8ZS0DIpkretKZmRB1VDhNqsAiOAWUTmg56xO7VZnlEvQRtyG8qyQHjlj6SDGtvxPDY58lz5nhIV9K6L7gHrOIcbSif5ZCt0e4DrKGaYXgH+mwIh2TMC2OCU6Xr6FRVQ9fBhilqMXuFIIezShN0hZb6mUCLkLVOzBBRKuz17S2a8twsuxix7ixqJPsIF3sI88tbxrFkSGSM02dhrmyZbkMr586rktVBB4T+8A28HJr4l9jkU0uk3l3le5bMcXhEuDkJUBnwEXEXfZa8Lw4sg2VuFgw0Ah0kw0/mAorpsFahXstNgrHhy3HoPKDCw/a/sXL4+fE72I1L96Lb7HOxTrdhEGnd65W4mPlTnbGW9YDQqTfZgRlpuffqQuWWYXolw== user@example.net
restrict,pty,command="nethack" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDYuKamN4JXNYmolm+A9hM+xYanupG1VgbM/k0NwPiIPUdiU82IPbP7bunsngnOatSDyCrKrhL9FV3wuHFFBX0QE9KpS8bcIcT3ySsi3wgYV95P7anb7YhliDDx2w/QB97kCnAKjGFS1yphS6px0i9B29tGVJa22ODs/hebIKUCYKC9/+fnZ+bIqte1HctDP2lDBzMa/7j8BUXSwnTDXtAuEz5eSMIpv1ZdUdaSuO8xFbB0xrBHQJKuqboLPo3NSOCg6uhopO6GucZuNLJnqVLkyEPTKH0nv/8smz/q3v1GOGz8ZS0DIpkretKZmRB1VDhNqsAiOAWUTmg56xO7VZnlEvQRtyG8qyQHjlj6SDGtvxPDY58lz5nhIV9K6L7gHrOIcbSif5ZCt0e4DrKGaYXgH+mwIh2TMC2OCU6Xr6FRVQ9fBhilqMXuFIIezShN0hZb6mUCLkLVOzBBRKuz17S2a8twsuxix7ixqJPsIF3sI88tbxrFkSGSM02dhrmyZbkMr586rktVBB4T+8A28HJr4l9jkU0uk3l3le5bMcXhEuDkJUBnwEXEXfZa8Lw4sg2VuFgw0Ah0kw0/mAorpsFahXstNgrHhy3HoPKDCw/a/sXL4+fE72I1L96Lb7HOxTrdhEGnd65W4mPlTnbGW9YDQqTfZgRlpuffqQuWWYXolw== user@example.net
no-touch-required sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBDisiCPxccUDt150qVkIZ5xc0qNyijG8i/WpAfENu2KBe3VXRBo0LxG7d+MMldTzC7QUjptAnZ2m1yyKgcK458sAAAAEc3NoOg== user@example.net
`

	entries, err := Parse(strings.NewReader(content))
	require.NoError(t, err)
	assert.Equal(t, 9, len(entries))
	assert.Equal(t, "user@example.net", entries[0].Label)
	assert.Equal(t, "ssh-rsa", entries[0].Key.Type())

	// Line is the physical 1-based line in the file: the first key sits on
	// line 3 (after a leading blank line and a comment), and the next on line 4.
	assert.Equal(t, int64(3), entries[0].Line)
	assert.Equal(t, int64(4), entries[1].Line)

	// The ssh-rsa fixture is a 4096-bit RSA key, so Bits reports its modulus
	// size in bits.
	assert.Equal(t, int64(4096), entries[0].Bits())

	assert.Equal(t, "AAAAB3NzaC1yc2EAAAADAQABAAACAQDYuKamN4JXNYmolm+A9hM+xYanupG1VgbM/k0NwPiIPUdiU82IPbP7bunsngnOatSDyCrKrhL9FV3wuHFFBX0QE9KpS8bcIcT3ySsi3wgYV95P7anb7YhliDDx2w/QB97kCnAKjGFS1yphS6px0i9B29tGVJa22ODs/hebIKUCYKC9/+fnZ+bIqte1HctDP2lDBzMa/7j8BUXSwnTDXtAuEz5eSMIpv1ZdUdaSuO8xFbB0xrBHQJKuqboLPo3NSOCg6uhopO6GucZuNLJnqVLkyEPTKH0nv/8smz/q3v1GOGz8ZS0DIpkretKZmRB1VDhNqsAiOAWUTmg56xO7VZnlEvQRtyG8qyQHjlj6SDGtvxPDY58lz5nhIV9K6L7gHrOIcbSif5ZCt0e4DrKGaYXgH+mwIh2TMC2OCU6Xr6FRVQ9fBhilqMXuFIIezShN0hZb6mUCLkLVOzBBRKuz17S2a8twsuxix7ixqJPsIF3sI88tbxrFkSGSM02dhrmyZbkMr586rktVBB4T+8A28HJr4l9jkU0uk3l3le5bMcXhEuDkJUBnwEXEXfZa8Lw4sg2VuFgw0Ah0kw0/mAorpsFahXstNgrHhy3HoPKDCw/a/sXL4+fE72I1L96Lb7HOxTrdhEGnd65W4mPlTnbGW9YDQqTfZgRlpuffqQuWWYXolw==", entries[0].Base64Key())
}

// ed25519 public key used by the long-line tests.
const longLineTestKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqaL8uRjdQQKUY9KQtT8OjKsHoy0fuULUq559ia82NJ"

// longFromOption returns a from="..." option listing 12,000 addresses
// (about 150 KB), the shape of a large allow list that sshd accepts.
func longFromOption() string {
	var b strings.Builder
	b.WriteString(`from="`)
	for a := 0; a < 2; a++ {
		for c := 0; c < 30; c++ {
			for d := 0; d < 200; d++ {
				fmt.Fprintf(&b, "10.%d.%d.%d,", a, c, d)
			}
		}
	}
	b.WriteString(`127.0.0.1"`)
	return b.String()
}

// sshd reads authorized_keys with getline(3), so a line of any length is
// one entry and the keys after it are still accepted. A parser that stops
// at a long line hides every later key from the scan.
func TestParseKeepsKeysAfterLongLine(t *testing.T) {
	long := longFromOption() + " " + longLineTestKey + " long-options"
	require.Greater(t, len(long), 64*1024)
	content := longLineTestKey + " first\n" + long + "\n" + longLineTestKey + " hidden-after-long-line\n"

	entries, err := Parse(strings.NewReader(content))
	require.NoError(t, err)
	require.Len(t, entries, 3)
	assert.Equal(t, "long-options", entries[1].Label)
	assert.Equal(t, int64(2), entries[1].Line)
	require.Len(t, entries[1].Options, 1)
	assert.True(t, strings.HasSuffix(entries[1].Options[0], `127.0.0.1"`))
	assert.Equal(t, "hidden-after-long-line", entries[2].Label)
	assert.Equal(t, int64(3), entries[2].Line)
}

// A line too long to read must fail the parse rather than return the keys
// read so far as if they were the whole file.
func TestParseErrorsOnLineOverLimit(t *testing.T) {
	content := longLineTestKey + " first\n" + strings.Repeat("x", maxLineBytes+1) + "\n" + longLineTestKey + " after\n"
	_, err := Parse(strings.NewReader(content))
	require.Error(t, err)
}
