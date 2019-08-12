package ssh

import (
	"bytes"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

var reg = regexp.MustCompile(`\[(.*?)\@(.*?) (.*?)\]# `)

type Write struct {
	commandResp  []byte
	isNewCommand bool
	done         chan struct{}
}

func (w *Write) Write(p []byte) (n int, err error) {
	if !w.isNewCommand {
		w.isNewCommand = true
		w.commandResp = make([]byte, 0, len(p))
	}

	if idx := reg.FindIndex(p); len(idx) > 0 {
		// fmt.Println(":", string(p[idx[0]:idx[1]]))
		go func() {
			w.done <- struct{}{}
		}()
		w.commandResp = append(w.commandResp, bytes.Replace(p, p[idx[0]:idx[1]], []byte{}, 1)...)
		w.isNewCommand = false
	} else {
		w.commandResp = append(w.commandResp, p...)
	}
	return len(p), nil
}

func NewWrite() *Write {
	return &Write{
		done: make(chan struct{}),
	}
}

type Read struct {
	lines chan string
	close chan struct{}
}

func NewRead() *Read {
	return &Read{
		lines: make(chan string),
		close: make(chan struct{}),
	}
}

func (r *Read) Close() {
	r.close <- struct{}{}
}

func (r *Read) Send(command string) {
	r.lines <- command
}

func (r *Read) Read(p []byte) (n int, err error) {
	select {
	case line := <-r.lines:
		{
			bs := []byte(line + "\n")
			copy(p, bs)
			return len(bs), nil
		}
	case <-r.close:
		{
			return 0, io.EOF
		}
	case <-time.After(1 * time.Second):
		{
			return 0, nil
		}
	}
}

type Client struct {
	*ssh.Client
}

func (c *Client) NewSession() (*Session, error) {
	session, err := c.Client.NewSession()
	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	// Request pseudo terminal
	if err := session.RequestPty("term", 40, 80, modes); err != nil {
		return nil, err
	}
	r := NewRead()
	w := NewWrite()
	session.Stdin = r
	session.Stdout = w
	session.Stderr = ioutil.Discard
	// Start remote shell
	if err := session.Shell(); err != nil {
		return nil, err
	}
	<-w.done
	return &Session{Session: session, w: w, r: r}, err
}

type Session struct {
	*ssh.Session
	r *Read
	w *Write
}

func (s *Session) Send(command string) *Resp {
	s.r.Send(command)
	<-s.w.done

	return &Resp{resp: s.w.commandResp}
}

type Resp struct {
	resp []byte
}

func (r *Resp) Int() int {
	i, _ := strconv.Atoi(string(r.resp))
	return i
}

func (r *Resp) String() string {
	return string(r.resp)
}

type ClientConfig struct {
	Addr       string
	User       string
	Passwrod   string
	PrivateKey []byte

	authMethod []ssh.AuthMethod
}

func (conf *ClientConfig) init() error {
	if conf.User == "" {
		conf.User = "root"
	}
	if conf.Passwrod != "" {
		conf.authMethod = []ssh.AuthMethod{
			ssh.Password(conf.Passwrod),
		}
	} else if len(conf.PrivateKey) == 0 {
		var privatePath string
		if runtime.GOOS == "windows" {
			privatePath = os.Getenv("USERPROFILE") + "/.ssh/id_rsa"
		} else if runtime.GOOS == "linux" {
			privatePath = "~/.ssh/id_rsa"
		}
		pbs, err := ioutil.ReadFile(privatePath)
		if err != nil {
			return err
		}
		conf.PrivateKey = pbs
	}
	if len(conf.PrivateKey) > 0 {
		method, err := ssh.ParsePrivateKey(conf.PrivateKey)
		if err != nil {
			return err
		}
		conf.authMethod = []ssh.AuthMethod{
			ssh.PublicKeys(method),
		}
	}
	return nil
}

func (conf *ClientConfig) parse() (*ssh.ClientConfig, error) {
	err := conf.init()
	if err != nil {
		return nil, err
	}
	cf := &ssh.ClientConfig{
		User: conf.User,
		Auth: conf.authMethod,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	return cf, nil
}

func NewClient(conf *ClientConfig) (*Client, error) {
	sshConfig, err := conf.parse()
	if err != nil {
		return nil, err
	}
	client, err := ssh.Dial("tcp", conf.Addr, sshConfig)
	if err != nil {
		return nil, err
	}
	return &Client{Client: client}, nil
}
