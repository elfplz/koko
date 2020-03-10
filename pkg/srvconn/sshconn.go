package srvconn

import (
	"errors"
	"io"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/gliderlabs/ssh"

	"github.com/jumpserver/koko/pkg/logger"
	"github.com/jumpserver/koko/pkg/model"
)

type ServerSSHConnection struct {
	User            *model.User
	Asset           *model.Asset
	SystemUser      *model.SystemUser
	Overtime        time.Duration
	CloseOnce       *sync.Once
	ReuseConnection bool

	client  *SSHClient
	session *gossh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
}

func (sc *ServerSSHConnection) SetSSHClient(client *SSHClient) {
	if client != nil {
		sc.client = client
	}
}

func (sc *ServerSSHConnection) Protocol() string {
	return "ssh"
}

func (sc *ServerSSHConnection) invokeShell(clientSess ssh.Session, h, w int, term string) (err error) {
	sess, err := sc.client.NewSession()
	if err != nil {
		return
	}
	sc.session = sess

	// 处理 x11 请求，需要在 pty-req, shell 请求之前做
	if clientSess != nil {
		err := sc.HandleX11Proxy(clientSess)
		if err != nil {
			logger.Errorf("handle x11 failed, err: %s", err)
		}
	}

	modes := gossh.TerminalModes{
		gossh.ECHO:          1,     // enable echoing
		gossh.TTY_OP_ISPEED: 14400, // input speed = 14.4 kbaud
		gossh.TTY_OP_OSPEED: 14400, // output speed = 14.4 kbaud
	}
	err = sess.RequestPty(term, h, w, modes)
	if err != nil {
		return
	}
	sc.stdin, err = sess.StdinPipe()
	if err != nil {
		return
	}
	sc.stdout, err = sess.StdoutPipe()
	if err != nil {
		return
	}
	err = sess.Shell()
	return err
}

func (sc *ServerSSHConnection) Connect(clientSess ssh.Session, h, w int, term string) (err error) {
	if sc.client == nil {
		sc.client, err = NewClient(sc.User, sc.Asset, sc.SystemUser, sc.Timeout(), sc.ReuseConnection)
		if err != nil {
			logger.Errorf("New SSH client err: %s", err)
			return
		}
	}
	err = sc.invokeShell(clientSess, h, w, term)
	if err != nil {
		logger.Errorf("SSH client %p start ssh shell session err %s", sc.client, err)
		RecycleClient(sc.client)
		return
	}
	logger.Infof("SSH client %p start ssh shell session success", sc.client)
	return
}

func (sc *ServerSSHConnection) HandleX11Proxy(clientSess ssh.Session) (err error) {
	if clientSess.X11ReqPayload() == nil {
		return nil
	}
	sess := sc.session
	// 请求远端开启 X11 转发
	ok, err := sess.SendRequest("x11-req", true, clientSess.X11ReqPayload())
	if err == nil && !ok {
		err = errors.New("ssh: x11-req failed")
	}

	if err == nil {
		// 处理转发
		x11channels := sc.client.client.HandleChannelOpen("x11")
		go func() {
			for ch := range x11channels {
				remoteCh, _, err := ch.Accept()
				remotePayload := ch.ExtraData()
				if err != nil {
					continue
				}
				// 对应开一个 channel 到用户
				clientConn := clientSess.Context().Value(ssh.ContextKeyConn).(*gossh.ServerConn)
				clientCh, clientReqCh, err := clientConn.OpenChannel("x11", remotePayload)
				if err != nil {
					continue
				}
				go func() {
					defer clientCh.Close()
					defer remoteCh.Close()
					io.Copy(clientCh, remoteCh)
				}()
				go func() {
					defer clientCh.Close()
					defer remoteCh.Close()
					io.Copy(remoteCh, clientCh)
				}()
				go func() {
					// PuTTY 会发送 Type 为 winadj@putty.projects.tartarus.org 请求来测算 window size
					// https://tartarus.org/~simon/putty-snapshots/htmldoc/Chapter4.html#config-ssh-bug-winadj
					// 对于这种请求，需要返回不认识
					for clientReq := range clientReqCh {
						clientReq.Reply(false, nil)
					}
				}()
			}
		}()
	}

	return err
}

func (sc *ServerSSHConnection) SetWinSize(h, w int) error {
	return sc.session.WindowChange(h, w)
}

func (sc *ServerSSHConnection) Read(p []byte) (n int, err error) {
	return sc.stdout.Read(p)
}

func (sc *ServerSSHConnection) Write(p []byte) (n int, err error) {
	return sc.stdin.Write(p)
}

func (sc *ServerSSHConnection) Timeout() time.Duration {
	if sc.Overtime == 0 {
		sc.Overtime = 30 * time.Second
	}
	return sc.Overtime
}

func (sc *ServerSSHConnection) Close() (err error) {
	sc.CloseOnce.Do(func() {
		RecycleClient(sc.client)

	})
	return sc.session.Close()
}
