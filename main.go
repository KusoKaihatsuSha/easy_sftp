// main.go
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

type FabricWorkers struct {
	Jobs      chan (Job)
	Results   chan (Result)
	Done      chan bool
	Wg        *sync.WaitGroup
	startTime time.Time
	endTime   time.Time
}

type frun func(interface{}) bool

type fres func(interface{})

type Job struct {
	id      frun
	idr     fres
	element interface{}
}
type Result struct {
	job  Job
	done bool
}

type Cred struct {
	Port          string
	Move          bool
	Login         string
	Password      string
	FindMask      string
	RenameMask    string
	RenameValue   string
	FindSubfolder bool
	PathLogs      string
	PathTo        string
	PathFrom      string
	TimeStamp     bool
	SepSymbol     string
	Logs          []string
	Debug         bool
	Salt          string
}

type Sftp struct {
	Server       string
	SftpIsOrigin bool
	SftpIsDest   bool
	Client       *sftp.Client
	Conn         *ssh.Client
	Cred         *Cred
}

type File struct {
	ServerSide  bool
	Fullname    string
	FullnameTmp string
	Name        string
	NameTmp     string
	Size        int64
	Hash        string
	DateMod     time.Time
	AfterCopy   *FileRet
}

type FileRet struct {
	ServerSide  bool
	Fullname    string
	FullnameTmp string
	Name        string
	NameTmp     string
	Size        int64
	DateMod     time.Time
	Hash        string
}

type Scan struct {
	Server      *Sftp
	Mask        string
	FilesOrigin map[string]*File
	FilesDest   map[string]*File
	FuncFill    func(interface{})
	FuncRun     func(interface{}) bool
	FuncRes     func(interface{})
	S           Stats
}

type Stats struct {
	Count  int
	Good   int
	Bad    int
	Errors int
}

var p = fmt.Println

// Init()
// init flags
func (o *Cred) Init() {
	o.Salt = srand(10, 10, true)
	flag.BoolVar(&o.Move, "m", false, "Accept values: copy or move. If value is empty => copy")
	flag.StringVar(&o.Login, "u", "user", "Accept values: exist user sftp login. If value is empty => user")
	flag.StringVar(&o.Password, "p", "password", "Accept values: exist user sftp pass. If value is empty => password")
	flag.StringVar(&o.Port, "port", "22", "Accept values: usage port sftp. If value is empty => 22")
	flag.StringVar(&o.PathFrom, "from", "anypathfromcopymove", "Accept values: local or sftp path. If value is sftp path use prefix serversftp@/somepath")
	flag.StringVar(&o.PathTo, "to", "anypathtocopymove", "Accept values: local or sftp path. If value is sftp path use prefix serversftp@/somepath")
	flag.StringVar(&o.FindMask, "mask", ".*", "Accept values: regexp mask.  If value is empty select all files => .*")
	flag.BoolVar(&o.TimeStamp, "ts", false, "Accept values: true or false for add suffix timestamp.  If value is empty => false")
	flag.BoolVar(&o.FindSubfolder, "sf", false, "Accept values: true or false for find in subfolder.  If value is empty => false")
	flag.StringVar(&o.PathLogs, "logs", "", "Accept values: path to folder with logs.  If value is empty => logs off")
	flag.StringVar(&o.SepSymbol, "symbol", "@", "Accept values: path to folder with logs.  If value is empty => logs off")
	flag.BoolVar(&o.Debug, "debug", false, "Accept values: true or false for more logs.  If value is empty => false")
	flag.Parse()
	if strings.Trim(o.Port, " ") != "" {
		o.Port = ":" + o.Port
	}
	symb := "->"
	if o.Move {
		symb = "->>>"
	}
	o.ToLogs(o.PathFrom + "(" + o.FindMask + ") " + symb + " " + o.PathTo)
}

// ToLogs(string)
// add to log file
func (o *Cred) ToLogs(text string) {
	o.Logs = append(o.Logs, o.Salt+":"+text)
}

// SaveLogs()
// save log file
func (o *Cred) SaveLogs() {
	if strings.Trim(o.PathLogs, "") != "" {
		f, _ := os.OpenFile(o.PathLogs+"logs"+time.Now().Format("_2006_01")+".txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		defer f.Close()
		log.SetOutput(f)
		for _, text := range o.Logs {
			log.Println(text)
		}
	}
}

// Init() bool
// init data for connect
func (o *Sftp) Init() bool {
	pathFromServer := ""
	pathToServer := ""
	pathFromServer, o.Cred.PathFrom = separate(o.Cred.PathFrom, o.Cred.SepSymbol)
	pathToServer, o.Cred.PathTo = separate(o.Cred.PathTo, o.Cred.SepSymbol)
	if pathFromServer != pathToServer && pathFromServer != "" && pathToServer != "" {
		err := errors.New("two different sftp server? sorry, but need one")
		o.Cred.ToLogs(err.Error())
		panic(err)
		return false
	} else {
		if pathFromServer != "" {
			o.Server = pathFromServer
			o.SftpIsOrigin = true
		}
		if pathToServer != "" {
			o.Server = pathToServer
			o.SftpIsDest = true
		}
	}
	if pathFromServer == "" && pathToServer == "" {
		err := errors.New("SFTP server not found in flags")
		o.Cred.ToLogs(err.Error())
		return false
	}
	return true
}

// Connect()
// connect to server
func (o *Sftp) Connect() {
	config := ssh.ClientConfig{
		User: o.Cred.Login,
		Auth: []ssh.AuthMethod{
			ssh.Password(o.Cred.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	var err error
	o.Conn, err = ssh.Dial("tcp", o.Server+o.Cred.Port, &config)
	if err != nil {
		o.Cred.ToLogs(err.Error())
		panic(err)
	} else {
		if o.Cred.Debug {
			o.Cred.ToLogs(o.Server + o.Cred.Port + " Server found")
		}
	}
	o.Client, err = sftp.NewClient(o.Conn)
	if err != nil {
		o.Cred.ToLogs(err.Error())
		panic(err)
	} else {
		if o.Cred.Debug {
			o.Cred.ToLogs(o.Server + o.Cred.Port + " Connect success")
		}
	}
}

// RemoveFile(string, bool) bool
// remove file
func (o *Sftp) RemoveFile(path string, isserver bool) bool {
	if isserver {
		err := o.Client.Remove(path)
		if err != nil {
			return false
		}
	} else {
		err := os.Remove(path)
		if err != nil {
			return false
		}
	}
	return true
}

// RenameFile(string, string, bool) bool
// rename file
func (o *Sftp) RenameFile(from, to string, isserver bool) bool {
	var err error
	if isserver {
		err = o.Client.Rename(from, to)
	} else {
		err = os.Rename(from, to)
	}
	if err != nil {
		o.Cred.ToLogs(err.Error())
		return false
	}
	return true
}

// CheckFile(string, bool) bool
// check exist file
func (o *Sftp) CheckFile(path string, server bool) bool {
	if server {
		_, errr := o.Client.Stat(path)
		if errr == nil {
			return true
		}
	} else {
		_, errr := os.Stat(path)
		if errr == nil {
			return true
		}
	}
	return false
}

// CheckHash(string, bool) string
// check hash between files
func (o *Sftp) CheckHash(path string, server bool) string {
	hfile := sha256.New()
	if server {
		file, _ := o.Client.OpenFile(path, os.O_RDONLY)
		if o.CheckFile(path, server) {
			io.Copy(hfile, file)
			closeFile(file)
		}
	} else {
		file, _ := os.OpenFile(path, os.O_RDONLY, 0664)
		if o.CheckFile(path, server) {
			io.Copy(hfile, file)
			closeFile(file)
		}
	}
	return hex.EncodeToString(hfile.Sum(nil))
}

// Disconnect()
// close connection
func (o *Sftp) Disconnect() {
	defer o.Client.Close()
	defer o.Conn.Close()
}

// Init()
// init app run
func (o *Scan) Init() {
	o.Server = new(Sftp)
	o.S.Count = 0
	o.S.Bad = 0
	o.S.Errors = 0
	o.S.Good = 0
	o.Server.Cred = new(Cred)
	o.Server.Cred.Init()
	if o.Server.Init() {
		o.Server.Connect()
	}
	//---init worker function
	o.FuncRun = o.CopyFile
	o.FuncRes = o.Statistic
}

// FileLockStat() (bool, time.Time)
// current locking stat
func (o *Scan) FileLockStat() (bool, time.Time) {
	str1 := "~~~!!!d!!!~~~"
	str2 := "~~~!!!o!!!~~~"
	if o.Server.SftpIsDest {
		f, errr := o.Server.Client.Stat(o.Server.Cred.PathTo + str1)
		if errr == nil {
			return true, f.ModTime()
		}
	} else {
		f, errr := os.Stat(o.Server.Cred.PathTo + str1)
		if errr == nil {
			return true, f.ModTime()
		}
	}
	if o.Server.SftpIsOrigin {
		f, errr := o.Server.Client.Stat(o.Server.Cred.PathFrom + str2)
		if errr == nil {
			return true, f.ModTime()
		}
	} else {
		f, errr := os.Stat(o.Server.Cred.PathFrom + str2)
		if errr == nil {
			return true, f.ModTime()
		}
	}
	return false, time.Now()
}

// Lock()
// lock files before sync
func (o *Scan) Lock() {
	for {
		if fls, t := o.FileLockStat(); fls {
			p(time.Since(t).Round(1*time.Second).Seconds(), time.Since(t).Round(1*time.Second).Seconds() > 3600)
			if time.Since(t).Round(1*time.Second).Seconds() > 3600 {
				o.Unlock()
			}
		} else {
			break
		}
		time.Sleep(5 * time.Second)
	}
	str1 := "~~~!!!d!!!~~~"
	str2 := "~~~!!!o!!!~~~"
	if fls, _ := o.FileLockStat(); !fls {
		if o.Server.SftpIsDest {
			file, err := o.Server.Client.Create(o.Server.Cred.PathTo + str1)
			defer file.Close()
			if err != nil {
				p(err)
			}

		} else {
			file, err := os.Create(o.Server.Cred.PathTo + str1)
			defer file.Close()
			if err != nil {
				p(err)
			}
		}
		if o.Server.SftpIsOrigin {
			file, err := o.Server.Client.Create(o.Server.Cred.PathFrom + str2)
			defer file.Close()
			if err != nil {
				p(err)
			}
		} else {
			file, err := os.Create(o.Server.Cred.PathFrom + str2)
			defer file.Close()
			if err != nil {
				p(err)
			}
		}
	}
}

// Unlock()
// unlock files after sync
func (o *Scan) Unlock() {
	str1 := "~~~!!!d!!!~~~"
	str2 := "~~~!!!o!!!~~~"
	if fls, _ := o.FileLockStat(); fls {
		if o.Server.SftpIsDest {
			o.Server.RemoveFile(o.Server.Cred.PathTo+str1, o.Server.SftpIsDest)
		} else {
			o.Server.RemoveFile(o.Server.Cred.PathTo+str1, o.Server.SftpIsDest)
		}
		if o.Server.SftpIsOrigin {
			o.Server.RemoveFile(o.Server.Cred.PathFrom+str2, o.Server.SftpIsOrigin)
		} else {
			o.Server.RemoveFile(o.Server.Cred.PathFrom+str2, o.Server.SftpIsOrigin)
		}
	}
}

// New()
// init task for sync
func (o *Scan) New() {
	o.FilesOrigin = make(map[string]*File)
	re := regexp.MustCompile(o.Server.Cred.FindMask)
	if o.Server.SftpIsOrigin {
		w := o.Server.Client.Walk(o.Server.Cred.PathFrom)
		for w.Step() {
			if w.Err() != nil {
				continue
			}
			if !w.Stat().IsDir() {
				fileDir := strings.TrimSuffix(w.Path(), w.Stat().Name())
				if !o.Server.Cred.FindSubfolder {
					if fileDir != o.Server.Cred.PathFrom {
						continue
					}
				}
				if !re.MatchString(w.Stat().Name()) {
					continue
				}
			} else {
				continue
			}
			var f File
			f.Fullname = w.Path()
			f.DateMod = w.Stat().ModTime()
			f.Name = w.Stat().Name()
			f.Size = w.Stat().Size()
			f.Hash = o.Server.CheckHash(w.Path(), true)
			f.ServerSide = true
			o.FilesOrigin[w.Path()] = &f
		}
	} else {
		err := filepath.Walk(o.Server.Cred.PathFrom, func(path string, info os.FileInfo, err error) error {
			fileDirDef := strings.Replace(o.Server.Cred.PathFrom, `\`, `/`, -1)
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				fileDir := strings.Replace(strings.TrimSuffix(path, info.Name()), `\`, `/`, -1)
				if !o.Server.Cred.FindSubfolder {
					if fileDir != fileDirDef {
						return nil
					}
				}
			} else {
				return nil
			}
			if !re.MatchString(info.Name()) {
				return nil
			}
			var f File
			f.Fullname = path
			f.Name = info.Name()
			f.DateMod = info.ModTime()
			f.Size = info.Size()
			f.Hash = o.Server.CheckHash(path, false)
			f.ServerSide = false
			o.FilesOrigin[path] = &f
			return nil
		})
		if err != nil {
			o.Server.Cred.ToLogs(err.Error())
			panic(err)
		}
	}
}

// CopyFile(ff interface{}) bool
//
func (o *Scan) CopyFile(file_ interface{}) bool {
	f := file_.(*File)
	if o.Server.CheckFile(o.Server.Cred.PathFrom+f.Name, o.Server.SftpIsOrigin) {
		if o.Coping(f) {
			return true
		}
	}
	return false
}

// Coping(f *File) bool
//
func (o *Scan) Coping(f *File) bool {
	var input []byte
	var err error
	if o.Server.SftpIsOrigin {
		file, err := o.Server.Client.Open(f.Fullname)
		if err != nil {
			return false
		}
		scanner := bufio.NewReader(file)
		input, err = ioutil.ReadAll(scanner)
		if err != nil {
			return false
		}
	} else {
		input, err = ioutil.ReadFile(f.Fullname)
		if err != nil {
			return false
		}
	}
	name_ := addTimeStr(f.Name, o.Server.Cred.TimeStamp)
	if o.Server.SftpIsDest {
		o.Server.Client.MkdirAll(o.Server.Cred.PathTo + "/")
		file, err := o.Server.Client.OpenFile(o.Server.Cred.PathTo+"/"+name_, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			return false
		}
		_, err = file.Write(input)
		if err != nil {
			return false
		} else {
			var nf FileRet
			nf_stet, _ := file.Stat()
			nf.Size = nf_stet.Size()
			nf.NameTmp = nf_stet.Name()
			nf.Name = name_
			nf.FullnameTmp = o.Server.Cred.PathTo + "/" + nf_stet.Name()
			nf.Fullname = o.Server.Cred.PathTo + "/" + name_
			nf.ServerSide = true
			nf.Hash = o.Server.CheckHash(o.Server.Cred.PathTo+"/"+nf_stet.Name(), true)
			f.AfterCopy = &nf
			err = o.Server.Client.Chtimes(o.Server.Cred.PathTo+"/"+nf_stet.Name(), f.DateMod, f.DateMod)
			if err != nil {
				p(err)
			}
		}
		closeFile(file)

	} else {
		os.MkdirAll(o.Server.Cred.PathTo+"/", 755)
		file, err := os.OpenFile(o.Server.Cred.PathTo+"/"+name_, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
		if err != nil {
			return false
		}
		_, err = file.Write(input)
		if err != nil {
			return false
		} else {
			var nf FileRet
			nf_stet, _ := file.Stat()
			nf.Size = nf_stet.Size()
			nf.NameTmp = nf_stet.Name()
			nf.Name = name_
			nf.FullnameTmp = o.Server.Cred.PathTo + "/" + nf_stet.Name()
			nf.Fullname = o.Server.Cred.PathTo + "/" + name_
			nf.ServerSide = false
			nf.Hash = o.Server.CheckHash(o.Server.Cred.PathTo+"/"+nf_stet.Name(), false)
			f.AfterCopy = &nf
			err = os.Chtimes(o.Server.Cred.PathTo+"/"+nf_stet.Name(), f.DateMod, f.DateMod)
			if err != nil {
				p(err.Error())
			}
		}
		closeFile(file)
	}
	if f.Hash == f.AfterCopy.Hash && f.Size == f.AfterCopy.Size {
		return true
	}
	return false
}

// Renaming(*File) bool
//
func (o *Scan) Renaming(f *File) bool {
	if f.Hash == f.AfterCopy.Hash && f.Size == f.AfterCopy.Size {
		if o.Server.RenameFile(f.AfterCopy.FullnameTmp, f.AfterCopy.Fullname, o.Server.SftpIsDest) {
			return true
		}
	}
	o.Server.Cred.ToLogs("Error Rename")
	return false
}

// Cleaning(*File) (bool, string)
//
func (o *Scan) Cleaning(f *File) (bool, string) {
	if f.Hash == f.AfterCopy.Hash && o.Server.Cred.Move && f.Size == f.AfterCopy.Size {
		if !o.Server.RemoveFile(f.Fullname, f.ServerSide) {
			return false, "Error deleting file"
		}
	}
	return true, ""
}

// RenamingError(*File) bool
//
func (o *Scan) RenamingError(f *File) bool {
	if f.Hash != f.AfterCopy.Hash || f.Size != f.AfterCopy.Size {
		if o.Server.RenameFile(f.AfterCopy.FullnameTmp, f.AfterCopy.Fullname+"_error_", o.Server.SftpIsDest) {
			return true
		}
	}
	o.Server.Cred.ToLogs("Error Rename")
	return false
}

// Statistic(interface{})
// logging statistic
func (o *Scan) Statistic(res interface{}) {
	result := res.(Result)
	o.S.Count++
	if result.job.element.(*File).AfterCopy != nil {
		if result.job.element.(*File).Hash == result.job.element.(*File).AfterCopy.Hash && result.job.element.(*File).Size == result.job.element.(*File).AfterCopy.Size {
			if val, add_ := o.Cleaning(result.job.element.(*File)); val {
				o.Server.Cred.ToLogs("[+]" + result.job.element.(*File).Name + "->" + result.job.element.(*File).AfterCopy.Name + "[" + ByteCountDecimal(result.job.element.(*File).AfterCopy.Size) + "/" + ByteCountDecimal(result.job.element.(*File).Size) + "]")
				o.S.Good++
			} else {
				o.Server.Cred.ToLogs("[-]" + result.job.element.(*File).Name + "->" + result.job.element.(*File).AfterCopy.Name + "[" + ByteCountDecimal(result.job.element.(*File).AfterCopy.Size) + "/" + ByteCountDecimal(result.job.element.(*File).Size) + "]" + add_)
				o.S.Bad++
			}
		} else {
			o.Server.Cred.ToLogs("[-]" + result.job.element.(*File).Name + "->" + result.job.element.(*File).AfterCopy.Name + "[" + ByteCountDecimal(result.job.element.(*File).AfterCopy.Size) + "/" + ByteCountDecimal(result.job.element.(*File).Size) + "]")
			o.S.Bad++
		}
	} else {
		o.Server.Cred.ToLogs("[-]" + result.job.element.(*File).Name + "->NULL " + "[" + " 0 /" + ByteCountDecimal(result.job.element.(*File).Size) + "]")
		o.S.Bad++
	}
}

// ByteCountDecimal(b int64) string
// check size and return string
func ByteCountDecimal(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

// FillWorkers() map[string]*File
//
func (o *Scan) FillWorkers() map[string]*File {
	return o.FilesOrigin
}

// init()
// init WP
func (o *FabricWorkers) init() {
	o.Jobs = make(chan Job, 4)
	o.Results = make(chan Result, 4)
	var wg sync.WaitGroup
	o.Wg = &wg
	o.Done = make(chan bool)
}

// end()
// done task
func (o *FabricWorkers) end() {
	<-o.Done
}

// worker()
// init worker
func (o *FabricWorkers) worker() {
	for job := range o.Jobs {
		output := Result{job, job.id(job.element)}
		o.Results <- output
	}
	o.Wg.Done()
}

// createWorkerPool()
// add workers to WP
func (o *FabricWorkers) createWorkerPool() {
	for i := 0; i < runtime.NumCPU(); i++ {
		o.Wg.Add(1)
		go o.worker()
	}
	o.Wg.Wait()
	close(o.Results)
}

// fillWorkers(frun, fres, interface{})
// fill workers and action task
func (o *FabricWorkers) fillWorkers(run frun, res fres, elements interface{}) {
	if reflect.ValueOf(elements).Kind() == reflect.Map {
		v := reflect.ValueOf(elements).MapRange()
		for v.Next() {
			f := v.Value()
			job := Job{run, res, f.Interface()}
			o.Jobs <- job
		}
	}
	close(o.Jobs)
}

// result()
// result of work
func (o *FabricWorkers) result() {
	for result := range o.Results {
		result.job.idr(result)
	}
	o.Done <- true
}

// Copy()
// run copy
func (o *Scan) Copy() {
	o.Server.Cred.ToLogs(">---------------------------------------->")
	work := new(FabricWorkers)
	work.startTime = time.Now()
	work.init()
	go work.fillWorkers(o.FuncRun, o.FuncRes, o.FilesOrigin)
	go work.result()
	go work.createWorkerPool()
	work.end()
	work.endTime = time.Now()
	o.Server.Cred.ToLogs("Total time " + work.endTime.Sub(work.startTime).String() + "")
	o.Server.Cred.ToLogs("Total Count: " + fmt.Sprintf("%d", o.S.Count) + "")
	o.Server.Cred.ToLogs("Count good: " + fmt.Sprintf("%d", o.S.Good) + "")
	o.Server.Cred.ToLogs("Count bad: " + fmt.Sprintf("%d", o.S.Bad) + "")
	o.Server.Cred.ToLogs("<----------------------------------------<")
	o.Server.Cred.SaveLogs()
}

// closeFile(interface{})
// close file
func closeFile(file interface{}) {
	switch file.(type) {
	case *sftp.File:
		file.(*sftp.File).Close()
	case *os.File:
		file.(*os.File).Close()
	default:
		p("Error! close")
	}
}

// separate(string, string) (string, string)
// split string by dilimiter
func separate(text, symbol string) (string, string) {
	vals := strings.Split(text, symbol)
	if len(vals) >= 2 && strings.Contains(text, symbol) {
		return vals[0], vals[1]
	} else {
		return "", text
	}
}

// addTimeStr(string, bool) string
// add strings timestamp
func addTimeStr(name string, confirm bool) string {
	if confirm == false {
		return name
	}
	arr := strings.Split(name, ".")
	if len(arr) > 1 {
		return strings.Join(arr[:len(arr)-1], ".") + "_" + time.Now().Format("20060102150405") + "." + arr[len(arr)-1]
	} else {
		return name
	}
}

// srand(int, int, bool) string
// random string
func srand(min, max int, readable bool) string {
	var length int
	var char string
	if min < max {
		length = min + rand.Intn(max-min)
	} else {
		length = min
	}
	if readable == false {
		char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	} else {
		char = "ABCDEFHJLMNQRTUVWXYZabcefghijkmnopqrtuvwxyz23479"
	}
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		buf[i] = char[rand.Intn(len(char)-1)]
	}
	return string(buf)
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	runtime.LockOSThread()
	runtime.Gosched()
	rand.Seed(time.Now().UTC().UnixNano())
}

func main() {
	scan := new(Scan)
	scan.Init()
	scan.New()
	scan.Copy()
}
