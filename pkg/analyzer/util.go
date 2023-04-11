package analyzer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os/exec"
)

func valueOrDefault(val, def string) string {
	if val == "" {
		return def
	}

	return val
}

func execute(ctx context.Context, name string, cmds []string) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, cmds...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	fmt.Print(stdout.String())
	return stdout.String(), stderr.String(), err
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
