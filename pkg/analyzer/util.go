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
	"regexp"
	"strconv"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/google/uuid"
)

var httpOrHttpsProtocol = regexp.MustCompile(`^https?://.+`)

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
	log.Printf("Start execute command: %s %s\n", name, strings.Join(cmds, " "))

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
		log.Println(error_buffer.String(), err)
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

func FixLinks(vuln *gabs.Container) {

	links := Map2(vuln.Path("links").Children(), func(link *gabs.Container) string {
		vulnUrlRaw, _ := link.Path("url").Data().(string)

		return fixUrlWithSpace(vulnUrlRaw)
	})

	links = Filter(links, isValidUrl)

	vuln.DeleteP("links")

	for _, l := range links {

		vuln.ArrayAppendP(map[string]interface{}{
			"url": l,
		}, "links")
	}
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

func FixImageAndOs(vuln *gabs.Container) {
	image, ok := vuln.Path("location.image").Data().(string)
	if !ok {
		return
	}

	image, os, ok := extractImageAndOs(image)
	if !ok {
		// TODO get image from envs
		return
	}

	vuln.SetP(image, "location.image")
	vuln.SetP(os, "location.operating_system")
}

func extractImageAndOs(image string) (string, string, bool) {
	index := strings.Index(image, " ")
	if index == -1 {
		return "", "", false
	}

	img := image[:index]
	if !strings.Contains(img, ":") {
		img = img + ":latest"
	}

	os := image[index+1:]
	os = os[1 : len(os)-1]
	return img, os, true
}
