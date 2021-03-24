package main

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

var (
	host      = flag.String("host", "github.com", "Host to test against")
	username  = flag.String("username", "git", "SSH username")
	listFiles = flag.Bool("list-files", false, "List matching files and exit")
)

var (
	beginMarker = []byte("-----BEGIN ")

	ghUsernameRE = regexp.MustCompile(`Hi ([^!]+)! You've successfully authenticated`)

	keyMarkers = [][]byte{
		[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----"),
		[]byte("-----BEGIN PRIVATE KEY-----"),
	}
)

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		log.Printf("usage: %s <directory>", os.Args[0])
		flag.Usage()
		os.Exit(1)
	}

	dir := args[0]

	var matchFiles []string

	_, _, err := net.SplitHostPort(*host)
	if err != nil {
		h := *host + ":22"
		host = &h
	}

	err = filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}

		if info.IsDir() {
			return nil
		}

		if info.Mode()&os.ModeSymlink == os.ModeSymlink {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		r := bufio.NewReader(f)
		for {
			line, err := r.ReadBytes('\n')
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}

			line = bytes.TrimLeft(line, " \t")
			if bytes.HasPrefix(line, beginMarker) {
				for _, keyMarker := range keyMarkers {
					if bytes.HasPrefix(line, keyMarker) {
						matchFiles = append(matchFiles, path)
						return nil
					}
				}
			}
		}

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	if *listFiles {
		for _, f := range matchFiles {
			fmt.Println(f)
		}
		os.Exit(0)
	}

	var activeKeys []string

	for _, f := range matchFiles {
		content, err := ioutil.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}

		for i := 0; ; i++ {
			var idx string
			if i > 0 {
				idx = fmt.Sprintf(" idx=%d", i)
			}

			block, rest := pem.Decode(content)
			if block == nil {
				break
			}
			content = rest

			pemBytes := pem.EncodeToMemory(block)

			log.Printf("Check %s%s", f, idx)
			ok, msg := checkCert(f, i, pemBytes)
			if ok {
				log.Printf("Valid %s%s\n%s\n%s", f, idx, msg, pemBytes)
				name := f
				match := ghUsernameRE.FindStringSubmatch(msg)
				if len(match) > 1 {
					name = name + " user: " + match[1]
				}
				activeKeys = append(activeKeys, name)
			} else {
				log.Printf("Invalid key %s%s", f, idx)
			}
		}
	}
	if len(activeKeys) > 0 {
		log.Println("Active keys:")
		for _, k := range activeKeys {
			fmt.Println(k)
		}
	} else {
		log.Println("No Active keys found")
	}

}

func checkCert(file string, idx int, block []byte) (bool, string) {
	key, err := ssh.ParseRawPrivateKey(block)
	if err != nil {
		log.Printf("Failed to parse key %d in %s, err: %s", idx, file, err)
		return false, ""
	}

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		log.Printf("Failed to make signer from key %d in %s, err: %s", idx, file, err)
		return false, ""
	}

	authMethod := ssh.PublicKeys(signer)
	config := &ssh.ClientConfig{
		User:            *username,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", *host, config)
	if err != nil {
		if strings.Index(err.Error(), "unable to authenticate") < 0 {
			// log errors besides 'unable to authenticate'
			log.Printf("Failed to dial: %s", err)
		}
		return false, ""
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		log.Printf("New Session error for %d %s: %s", idx, file, err)
	}
	defer sess.Close()

	var msg []byte
	r, err := sess.StderrPipe()
	if err != nil {
		panic(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 1024)
		for {
			n, err := r.Read(b)
			if n > 0 {
				msg = append(msg, b[:n]...)
			}
			if err == io.EOF {
				break
			} else if err != nil {
				panic(err)
			}
		}
	}()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sess.RequestPty("xterm", 40, 80, modes); err != nil {
		log.Printf("requestpty err: %s", err)
	} else {
		log.Printf("requestpty ok!")
	}
	// Start remote shell
	if err := sess.Shell(); err != nil {
		log.Printf("requestpty.shell err: %s", err)
	} else {
		log.Printf("request shell ok!")

	}

	sess.Close()
	client.Close()

	wg.Wait()

	log.Printf("connection success: %s/%d %s", file, idx, msg)
	return true, string(msg)

}
