package main

// TODO:
// 複数パラメータ
// 自動再接続
// パラメータをコマンドラインで指定
//
//	History
//	ver 1.0		initial release
//	ver 1.1		"[interval]" 指定機能追加
//	ver 1.2		-u option, DNS name

import (
	"bufio"
	"bytes"
	"container/heap"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const timeout = 10
const version = "1.2"
var errReadTimeout = errors.New("rx timed out")

// コマンド送信し、プロンプトを待ち、出力結果を返す
func sendCmd(w *worker, cmd string) (string, error) {
	_, err := w.in.Write([]byte(cmd + "\n"))
	if err != nil {
		w.log.Error("in.Write(): ", err)
		return "", err
	}

	r, err := readCli(w)
	return r, err
}

// Prompt が返るか、EOF になるまでバッファに読み込み、文字列にして返す
type readresp struct {
	n int
	err error
}

func readCli(w *worker) (string, error) {
	w.buf.Reset()
	var e error
	LOOP:
	for {
		go func() {
			n, err := w.out.Read(w.tmpbuf)
			if n > 0 {
				w.buf.Write(w.tmpbuf[:n])
			}
			w.respCh <-&readresp{n, err}
		}()
		select {
		case resp := <-w.respCh:
			e = resp.err
		case <-time.After(timeout * time.Second):
			e = errReadTimeout
			break LOOP
		}
		if e != nil {
			if errors.Is(e, io.EOF) {
				w.log.Warn("EOF reached.")
				e = nil
			}
			break
		}
		buf := w.buf.Bytes()
		if (isIap && bytes.HasSuffix(buf, []byte("# "))) ||			// IAP prompt
			(!isIap && bytes.HasSuffix(buf, []byte(") #"))) ||		// MD prompt
			(!isIap && bytes.HasSuffix(buf, []byte(") *#"))) {		// MD prompt with crashinfo
			break
		}
	}
	return strings.Replace(w.buf.String(), "\r", "", -1), e
}

// 現在時刻を示す文字列
func getnowstr() string {
	return time.Now().Format("2006-01-02 15:04:05.000 -0700")
}

// --------------------------------------------------------------------------------
type schedule struct {
	epoch int64
	cmdidx int
	ctr int
}

type worker struct {
	in io.Writer
	out io.Reader
	log *MyLogger
	buf bytes.Buffer
	tmpbuf []byte
	respCh chan *readresp
}

type heapq []schedule

// heap.Interface
func (q heapq) Len() int { return len(q) }
func (q heapq) Less(i, j int) bool {
	if q[i].epoch == q[j].epoch {
		return q[i].cmdidx < q[j].cmdidx
	}
	return q[i].epoch < q[j].epoch
}
func (q heapq) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (qp *heapq) Push(x interface{}) {
	*qp = append(*qp, x.(schedule))
}
func (qp *heapq) Pop() interface{} {
	q := *qp
	ret := q[len(q)-1]
	*qp = q[:len(q)-1]
	return ret
}

//
// ssh goroutine
//
func doSsh(host string, log *MyLogger, cancelCh chan struct{}) {
	defer wg.Done()

	var w worker
	w.log = log		// logger for this thread
	w.respCh = make(chan *readresp, 1)
	w.tmpbuf = make([]byte, 64*1024)

	// sanity check
	host = strings.Trim(host, " \t\r\n")
	//m, _ := regexp.MatchString(`^\d+\.\d+\.\d+\.\d+$`, host)
	//if !m {
	//	log.Error("invalid host: " + host)
	//	return
	//}

	// 記録ファイル作成
	fn := "log_" + host + "_" + time.Now().Format("20060102") + ".txt"
	fout, err := os.OpenFile(fn, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error("Can't create log file: ", err)
		return
	}
	defer fout.Close()
	bout := bufio.NewWriter(fout)
	defer bout.Flush()
	log.Infof("Log file %v created.", fn)

	fmt.Fprintln(bout, "\n<<<<<<<<<")
	fmt.Fprintln(bout, "<<<<<<<<< START script at", getnowstr())
	fmt.Fprintln(bout, "<<<<<<<<<")

	// schedule 初期化
	q := make(heapq, 0)
	for i:=0; i<len(cmdList); i++ {
		heap.Push(&q, schedule{ epoch: 0, cmdidx: i, ctr: 1 })
	}

	// ssh 接続パラメータ
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{ ssh.Password(passwd) },
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout: timeout * time.Second,		// connection timeout. (not read timeout)
	}

	// connect to host
	host += ":22"
	log.Debug("Connecting to " + host + " with user '" + username + "'...")
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		log.Error("Connection failed: ", err)
		fmt.Fprintln(bout, "Connection failed: " + err.Error())
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Error("Can't create session: ", err)
		fmt.Fprintln(bout, "Can't create session: " + err.Error())
		return
	}
	defer session.Close()

	// configure terminal mode
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // 0: suppress echo
	}
	// start terminal session
	if err := session.RequestPty("xterm", 50, 80, modes); err != nil {
		log.Error("RequestPty(): ", err)
		fmt.Fprintln(bout, "RequestPty(): " + err.Error())
		return
	}

	w.out, _ = session.StdoutPipe()
	w.in, _ = session.StdinPipe()

	// start remote shell
	if err := session.Shell(); err != nil {
		log.Error("Shell(): ", err)
		fmt.Fprintln(bout, "Shell(): " + err.Error())
		return
	}
	log.Info("Connection established for " + host)
	fmt.Println("Connection established for " + host)

	var r string
	var now, endtime int64
	var sched schedule
	var cmdinfo cmdInfo
	var e error

	// wait for prompt
	_, e = readCli(&w)
	if e != nil {
		log.Error("readCli: " + e.Error())
		fmt.Fprintln(bout, "Error: " + e.Error())
		return
	}

	// send "no paging"
	if !isIap {
		_, e = sendCmd(&w, "no paging")
		if e != nil {
			log.Error("sendCmd('no paging') failed: ", e)
			return
		}
	}

	if duration > 0 {
		endtime = time.Now().Unix() + duration
	} else {
		endtime = 1<<63 - 1		// int64 maximum
	}

	LOOP:
	for len(q) > 0 {
		now = time.Now().Unix()

		// 直近のスケジュール(epoch最小のもの)をPop
		sched = heap.Pop(&q).(schedule)
		//log.Debugf("got cmdset: epoch:%v, interval:%v, ctr:%v, number of cmds:%v", cmdset.epoch, cmdset.cmd, cmdset.ctr, len(cmdMap[cmdset.cmd]))
		if sched.epoch == 0 {	// first time
			sched.epoch = now
		}
		cmdinfo = cmdList[sched.cmdidx]
		// schedule next run
		if cmdinfo.itvl > 0 && (cmdinfo.iter <= 0 || (cmdinfo.iter > 0 && sched.ctr < cmdinfo.iter)) {
			nexttime := sched.epoch + cmdinfo.itvl
			if nexttime <= endtime {
				heap.Push(&q, schedule{ epoch: nexttime, cmdidx: sched.cmdidx, ctr: sched.ctr+1 })
			}
		}
		// epoch 時刻まで待つ
		if sched.epoch > now {
			log.Debugf("Sleeping %v seconds...", sched.epoch-now)
			select {
			case <-cancelCh:
				log.Warn("Canceling doSsh()!")
				break LOOP
			case <-time.After(time.Duration(sched.epoch-now) * time.Second):
			}
		}

		log.Debugf("Sending cmd[%v] (itvl:%3v, iter #%2v/%2v): \"%v\"", sched.cmdidx, cmdinfo.itvl, sched.ctr, cmdinfo.iter, cmdinfo.cmd)
		cmdstart := getnowstr()

		// コマンド送信
		r, e = sendCmd(&w, cmdinfo.cmd)
		if e != nil {
			log.Error("sendCmd() failed: ", e)
			fmt.Fprintln(bout, "failed to send command: " + e.Error())
			break LOOP
		}

		// コマンドログ記録
		fmt.Fprintln(bout, "\n\n/////")
		fmt.Fprintln(bout, "///// Begin Time: " + cmdstart)
		fmt.Fprintln(bout, "///// End Time:   " + getnowstr())
		fmt.Fprintf(bout,  "///// Inteval: %v sec, Iteration: #%v\n", cmdinfo.itvl, sched.ctr)
		fmt.Fprint(bout, "/////\n\n")
		bout.WriteString(r)

		// ウェイト
		time.Sleep(100*time.Millisecond)	// 100msec wait
		select {
		case <-cancelCh:
			log.Warn("Canceling ssh session to " + host)
			break LOOP
		default:
		}
	}
	log.Info("Closing ssh session to " + host)
}

var errInvalidIP = errors.New("invalid IP address")

func ipaddrParser(ip string) ([]string, error) {
	re := regexp.MustCompile(`^(\d+\.\d+\.\d+\.)([\d,-]+)$`)
	m := re.FindStringSubmatch(ip)
	if len(m) == 0 {
		return nil, errInvalidIP
	}

	ip1 := m[1]
	var ips []string
	var idx int

	for _, ip2 := range(strings.Split(m[2], ",")) {
		if len(ip2) == 0 {
			return nil, errInvalidIP
		}
		idx = strings.Index(ip2, "-")
		if idx != -1 {
			s, err := strconv.Atoi(ip2[:idx])
			if err != nil || s > 255 {
				return nil, errInvalidIP
			}
			e, err := strconv.Atoi(ip2[idx+1:])
			if err != nil || e > 255 {
				return nil, errInvalidIP
			}
			if e<=s {
				return nil, errInvalidIP
			}
			for ; s<=e; s++ {
				ips = append(ips, ip1 + strconv.Itoa(s))
			}
		} else {
			ips = append(ips, ip1 + ip2)
		}
	}

	return ips, nil
}
//
//  ------------------------------------------------------------------------------------------------
//		main
//  ------------------------------------------------------------------------------------------------
//

type cmdInfo struct {
	cmd string
	itvl int64
	iter int
}

var wg sync.WaitGroup
var username, passwd string
var cmdList []cmdInfo
var valMap map[string]string
var duration int64
var isIap, isDebug, isInfo bool
var cmdfile string

func main() {
	//var hostKey ssh.PublicKey
	log := NewMyLogger(warnLevel, "Main")
	platformInit()

	// print banner
	fmt.Printf("ssh-tool version %v\n", version)

	// parse flags
	flag.StringVar(&username, "u", "admin", "username")
	flag.StringVar(&passwd, "p", "", "password")
	flag.StringVar(&cmdfile, "c", "commands.txt", "command file")
	flag.Int64Var(&duration, "d", 0, "duration in seconds (0: indefinitely)")
	flag.BoolVar(&isIap, "iap", false, "target host is Instant AP")
	flag.BoolVar(&isDebug, "debug", false, "enable debug logs")
	flag.BoolVar(&isInfo, "info", false, "enable infomational logs")
	flag.Parse()

	// parse to end (cf. https://github.com/golang/go/issues/36744)
	args := make([]string, 0)
	for i := len(os.Args)-len(flag.Args())+1; i<len(os.Args); {
		if i > 1 && os.Args[i-2] == "--" {
			break
		}
		args = append(args, flag.Arg(0))
		flag.CommandLine.Parse(os.Args[i:])
		i += 1 + len(os.Args[i:]) - len(flag.Args())
	}
	args = append(args, flag.Args()...)

	// set loglevel
	if isDebug {
		log.loglevel = debugLevel
	} else if isInfo {
		log.loglevel = infoLevel
	}

	if len(args) == 0 {
		fmt.Println("Please specify device IP address(es).")
		os.Exit(1)
	}
	if passwd == "" {
		fmt.Print("Enter password: ")
		p, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("")
		passwd = string(p)
	}

	var iplist []string
	for _, ip := range args {
		ips, err := ipaddrParser(ip)
		if err != nil {
			// log.Error("invalid IP: ", ip)
			// os.Exit(1)
			iplist = append(iplist, ip)
		} else {
			iplist = append(iplist, ips...)
		}
	}

	log.Infof("%v hosts specified.", len(iplist))

	// commands.txt 読み込み
	f, err := os.Open(cmdfile)
	if err != nil {
		log.Error("failed to open command file: ", err)
		os.Exit(1)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	valMap = make(map[string]string)
	var l, itvl, cmd string
	var i, idx, iter, mulsec, num, def_int int
	var m []string
	re := regexp.MustCompile(`^(\d+[mh]?),|^(\d+[mh]?);(\d+),`)
	re2 := regexp.MustCompile(`^\[interval *=? *(\d+[mh]?)\]`)
	for sc.Scan() {
		l = strings.Trim(sc.Text(), " \t\r\n")
		if l == "" || l[0] == '#' { continue }		// skip null lines/comments

		// [interval=30] 指定
		m = re2.FindStringSubmatch(l)
		if m != nil {
			itvl = m[1]
			mulsec = 1
			if strings.HasSuffix(itvl, "m") {
				itvl = itvl[:len(itvl)-1]
				mulsec = 60
			} else if strings.HasSuffix(itvl, "h") {
				itvl = itvl[:len(itvl)-1]
				mulsec = 3600
			}
			def_int, err = strconv.Atoi(itvl)
			if err != nil {
				log.Error("invalid interval format: ", l)
				os.Exit(1)
			}
			def_int *= mulsec
			continue
		}

		// VARNAME=VALUE
		idx = strings.Index(l, "=")
		if idx != -1 {
			name  := strings.Trim(l[:idx], " \t\r\n")
			value := strings.Trim(l[idx+1:], " \t\r\n")
			if len(name) == 0 || len(value) == 0 {
				log.Error("invalid command format: ", l)
				os.Exit(1)
			}
			valMap[name] = subst(value, log)
			continue
		}

		l = subst(l, log)	// process $VAR and ${VAR}

		m = re.FindStringSubmatch(l)
		if len(m) == 0 {	// interval指定なし
			cmd = l
			if def_int == 0 {
				// 一度だけ実行
				i = 0
				iter = 1
			} else {
				// def_int 間隔で実行
				i = def_int
				iter = -1
			}
		} else {
			itvl = m[1]
			iter = -1
			if itvl == "" {
				itvl = m[2]
				iter, _ = strconv.Atoi(m[3])
			}
			cmd = strings.Trim(l[len(m[0]):], " \t\r\n")
			mulsec = 1
			if strings.HasSuffix(itvl, "m") {
				itvl = itvl[:len(itvl)-1]
				mulsec = 60
			} else if strings.HasSuffix(itvl, "h") {
				itvl = itvl[:len(itvl)-1]
				mulsec = 3600
			}
			i, err = strconv.Atoi(itvl)
			if err != nil {
				log.Error("invalid interval format: ", l)
				os.Exit(1)
			}
			i *= mulsec
		}
		cmdList = append(cmdList, cmdInfo{cmd: cmd, itvl: int64(i), iter: iter})
		log.Debugf("cmd[%v]: \"%v\", itvl: %v, iter: %v", num, cmd, i, iter)
		num ++
	}

	// channel
	cancelCh := make(chan struct{})
	completedCh := make(chan struct{})
	interruptCh := make(chan os.Signal, 1)
	signal.Notify(interruptCh, os.Interrupt)	// catch Ctrl+C (SIGINT) interrupt
	fmt.Println("Starting ssh sessions. Press Ctrl+C to abort.")

	// start ssh session
	go func() {
		for i, ip := range iplist {
			wg.Add(1)
			threadname := fmt.Sprintf("Thread%v", i+1)
			go doSsh(ip, CloneMyLogger(log, threadname), cancelCh)
			time.Sleep(100*time.Millisecond)		// 100msec delay for each doSsh() thread
		}
		wg.Wait()
		close(completedCh)
	}()

	for {
		select {
		case <-completedCh:
			log.Info("All goroutines completed.")
			return
		case <-interruptCh:
			log.Warn("Ctrl-C interrupt. cancelling...")
			close(cancelCh)
			interruptCh = nil
		}
	}
}

const (
	mod_TOUPPER = 1<<iota
	mod_TOLOWER
)

func subst(l string, log *MyLogger) string {
	// $NAME => VALUE
	// ${NAME} => VALUE
	var r strings.Builder
	re := regexp.MustCompile(`\$([\w:]+)|\$\{([\w:]+)\}`)
	idxs := re.FindAllStringSubmatchIndex(l, -1)
	var s, e, prev, mod int
	var name string
	for _, idx := range idxs {
		// idx[0], idx[1] がマッチ全体の range
		// idx[2], idx[3] が re.group(1) の range
		// idx[4], idx[5] が re.group(2) の range
		if idx[2] == -1 {
			s, e = idx[4], idx[5]
		} else {
			s, e = idx[2], idx[3]
		}

		name = l[s:e]
		mod = 0
		if strings.HasSuffix(name, ":lower") {
			name = name[:len(name)-6]
			mod |= mod_TOLOWER
		} else if strings.HasSuffix(name, ":upper") {
			name = name[:len(name)-6]
			mod |= mod_TOUPPER
		}

		r.WriteString(l[prev:idx[0]])
		if v, ok := valMap[name]; !ok {
			log.Errorf("Variable '%v' not defined in command file: %v", name, l)
			os.Exit(1)
		} else {
			switch {
			case mod & mod_TOLOWER != 0:
				v = strings.ToLower(v)
			case mod & mod_TOUPPER != 0:
				v = strings.ToUpper(v)
			}
			r.WriteString(v)
		}
		prev = idx[1]
	}

	r.WriteString(l[prev:])
	return r.String()
}
