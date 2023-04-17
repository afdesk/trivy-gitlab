package analyzer

import (
	"bytes"
	"io"
	"log"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
)

var httpOrHttpsProtocol = regexp.MustCompile(`^https?://.+`)

func piped(stack ...*exec.Cmd) (string, string, error) {
	var stdout bytes.Buffer
	var errorBuffer bytes.Buffer
	pipeStack := make([]*io.PipeWriter, len(stack)-1)
	i := 0
	for ; i < len(stack)-1; i++ {
		stdin_pipe, stdout_pipe := io.Pipe()
		stack[i].Stdout = stdout_pipe
		stack[i].Stderr = &errorBuffer
		stack[i+1].Stdin = stdin_pipe
		pipeStack[i] = stdout_pipe
	}
	stack[i].Stdout = &stdout
	stack[i].Stderr = &errorBuffer

	if err := call(stack, pipeStack); err != nil {
		log.Println(errorBuffer.String(), err)
		return "", "", err
	}
	return stdout.String(), errorBuffer.String(), nil
}

func call(stack []*exec.Cmd, pipes []*io.PipeWriter) (err error) {
	if stack[0].Process == nil {
		if err = stack[0].Start(); err != nil {
			return err
		}
	}
	if len(stack) > 1 {
		if err = stack[1].Start(); err != nil {
			return err
		}
		defer func() {
			if err == nil {
				pipes[0].Close()
				err = call(stack[1:], pipes[1:])
			}
		}()
	}
	return stack[0].Wait()
}

func fixUrlWithSpace(u string) string {
	if spaceIndex := strings.Index(u, " "); spaceIndex != -1 {
		return u[:spaceIndex]
	}
	return u
}

func isHttpOrHttps(u string) bool {
	return httpOrHttpsProtocol.MatchString(u)
}

func isValidUrl(u string) bool {
	url, err := url.ParseRequestURI(u)
	if err != nil {
		log.Println(err)
		return false
	}

	// "ftp://ftp.sco.com/pub/updates/OpenServer/SCOSA-2005.3/SCOSA-2005.3.txt
	if !isHttpOrHttps(url.String()) {
		return false
	}
	return true
}
