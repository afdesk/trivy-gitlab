package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/url"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/google/uuid"
)

func valueOrDefault(val, def string) string {
	if val == "" {
		return def
	}

	return val
}

func execute(ctx context.Context, name string, cmds []string) error {

	cmd := exec.CommandContext(ctx, name, cmds...)

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	fmt.Printf("Start execute command: %s %s\n", name, strings.Join(cmds, " "))

	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		m := scanner.Text()
		fmt.Println(m)
	}
	cmd.Wait()
	return nil
}

func piped(stack ...*exec.Cmd) (string, string, error) {
	var stdout bytes.Buffer
	var error_buffer bytes.Buffer
	pipe_stack := make([]*io.PipeWriter, len(stack)-1)
	i := 0
	for ; i < len(stack)-1; i++ {
		stdin_pipe, stdout_pipe := io.Pipe()
		stack[i].Stdout = stdout_pipe
		stack[i].Stderr = &error_buffer
		stack[i+1].Stdin = stdin_pipe
		pipe_stack[i] = stdout_pipe
	}
	stack[i].Stdout = &stdout
	stack[i].Stderr = &error_buffer

	if err := call(stack, pipe_stack); err != nil {
		log.Fatalln(error_buffer.String(), err)
		return "", "", err
	}
	return stdout.String(), "", nil
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

func QuoteStrToInt(s string) (int, error) {
	line, err := strconv.Unquote(s)
	if err != nil {
		return -1, err
	}
	i, err := strconv.Atoi(line)
	if err != nil {
		return -1, err
	}

	return i, nil
}

// Convert str line number to int
func FixLineNumbers(vuln *gabs.Container) {
	strLineToInt := func(path string) error {
		rawLine := vuln.Path(path)

		i, err := QuoteStrToInt(rawLine.String())

		if err != nil {
			return err
		}

		vuln.SetP(i, path)
		return nil
	}

	for _, s := range []string{"location.start_line", "location.end_line"} {
		if err := strLineToInt(s); err != nil {
			log.Println(err)
		}
	}
}

func FixId(vuln *gabs.Container) {
	vuln.Set(uuid.New().String(), "id")
}

// Fix follow: https://aomedia.googlesource.com/aom/+/94bcbfe76b0fd5b8ac03645082dc23a88730c949 (v2.0.1)
func FixLinks(vuln *gabs.Container) {
	for _, link := range vuln.Path("links").Children() {
		vulnUrlRaw := link.Path("url").String()
		vulnUrl, err := strconv.Unquote(vulnUrlRaw)
		if err != nil {
			log.Println(err)
			continue
		}

		if !strings.Contains(vulnUrl, " ") {
			continue
		}

		splitedUrl := strings.Split(vulnUrl, " ")
		if _, err := url.ParseRequestURI(splitedUrl[0]); err == nil {
			link.SetP(splitedUrl[0], "url")
		}
	}
}
