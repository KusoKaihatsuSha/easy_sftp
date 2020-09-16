// main.go
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/pkg/sftp"
	. "github.com/ulvham/helper"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"

	//"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

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
}

type CredObj interface {
	Init()
	ToLogs(string)
	SaveLogs()
}

func (obj *Cred) Init() {
	flag.BoolVar(&obj.Move, "m", false, "Accept values: copy or move. If value is empty => copy")
	flag.StringVar(&obj.Login, "u", "user", "Accept values: exist user sftp login. If value is empty => user")
	flag.StringVar(&obj.Password, "p", "password", "Accept values: exist user sftp pass. If value is empty => password")
	flag.StringVar(&obj.Port, "port", "22", "Accept values: usage port sftp. If value is empty => 22")
	flag.StringVar(&obj.PathFrom, "from", "anypathfromcopymove", "Accept values: local or sftp path. If value is sftp path use prefix serversftp@/somepath")
	flag.StringVar(&obj.PathTo, "to", "anypathtocopymove", "Accept values: local or sftp path. If value is sftp path use prefix serversftp@/somepath")
	flag.StringVar(&obj.FindMask, "mask", ".*", "Accept values: regexp mask.  If value is empty select all files => .*")
	flag.BoolVar(&obj.TimeStamp, "ts", false, "Accept values: true or false for add suffix timestamp.  If value is empty => false")
	flag.BoolVar(&obj.FindSubfolder, "sf", false, "Accept values: true or false for find in subfolder.  If value is empty => false")
	flag.StringVar(&obj.PathLogs, "logs", "", "Accept values: path to folder with logs.  If value is empty => logs off")
	flag.StringVar(&obj.SepSymbol, "symbol", "@", "Accept values: path to folder with logs.  If value is empty => logs off")
	flag.BoolVar(&obj.Debug, "debug", false, "Accept values: true or false for more logs.  If value is empty => false")
	flag.Parse()
	//
	//obj.Debug = false
	//
	if strings.Trim(obj.Port, " ") != "" {
		obj.Port = ":" + obj.Port
	}
	symb := "->"
	if obj.Move {
		symb = "->>>"
	}
	obj.ToLogs(obj.PathFrom + "(" + obj.FindMask + ") " + symb + " " + obj.PathTo)
}

func (obj *Cred) ToLogs(text string) {
	obj.Logs = append(obj.Logs, text)
	p(text)
}

func (obj *Cred) SaveLogs() {
	if strings.Trim(obj.PathLogs, "") != "" {
		f, _ := os.OpenFile(obj.PathLogs+"logs.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		defer f.Close()
		log.SetOutput(f)
		for _, text := range obj.Logs {
			log.Println(text)
		}

	}
}

type Sftp struct {
	Server       string
	SftpIsOrigin bool
	SftpIsDest   bool
	Client       *sftp.Client
	Conn         *ssh.Client
	Cred         *Cred
}

type SftpObj interface {
	Init() bool
	Connect()
	Disconnect()
	CheckHash(string, bool)
	RemoveFile(string, bool)
}

func (obj *Sftp) Init() bool {
	pathFromServer := ""
	pathToServer := ""
	pathFromServer, obj.Cred.PathFrom = separate(obj.Cred.PathFrom, obj.Cred.SepSymbol)
	pathToServer, obj.Cred.PathTo = separate(obj.Cred.PathTo, obj.Cred.SepSymbol)
	if pathFromServer != pathToServer && pathFromServer != "" && pathToServer != "" {
		err := errors.New("two different sftp server? sorry, but need one")
		if obj.Cred.Debug {
			obj.Cred.ToLogs(err.Error())
		}
		panic(err)
		return false
	} else {
		if pathFromServer != "" {
			obj.Server = pathFromServer
			obj.SftpIsOrigin = true
		}
		if pathToServer != "" {
			obj.Server = pathToServer
			obj.SftpIsDest = true
		}
	}
	if pathFromServer == "" && pathToServer == "" {
		err := errors.New("SFTP server not found in flags")
		if obj.Cred.Debug {
			obj.Cred.ToLogs(err.Error())
		}
		return false
		//panic(err)
	}
	return true
}

func (obj *Sftp) Connect() {
	config := ssh.ClientConfig{
		User: obj.Cred.Login,
		Auth: []ssh.AuthMethod{
			ssh.Password(obj.Cred.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	var err error
	obj.Conn, err = ssh.Dial("tcp", obj.Server+obj.Cred.Port, &config)
	if err != nil {
		obj.Cred.ToLogs(err.Error())
		panic(err)
	} else {
		if obj.Cred.Debug {
			obj.Cred.ToLogs(obj.Server + obj.Cred.Port + " Server found")
		}
	}
	obj.Client, err = sftp.NewClient(obj.Conn)
	if err != nil {
		obj.Cred.ToLogs(err.Error())
		panic(err)
	} else {
		if obj.Cred.Debug {
			obj.Cred.ToLogs(obj.Server + obj.Cred.Port + " Connect success")
		}
	}
}

func (obj *Sftp) RemoveFile(path string, isserver bool) bool {
	if isserver {
		err := obj.Client.Remove(path)
		if err != nil {
			obj.Cred.ToLogs(err.Error())
			return false
		}
	} else {
		err := os.Remove(path)
		if err != nil {
			obj.Cred.ToLogs(err.Error())
			return false
		}
	}
	return true
}

func (obj *Sftp) RenameFile(pathfrom string, pathto string, isserver bool) bool {

	var err error
	if isserver {
		_, errr := obj.Client.Stat(pathto)
		if errr == nil {
			if !obj.RemoveFile(pathto, isserver) {
				obj.Cred.ToLogs("Error deleting file - " + pathto)
				return false
			}
		}
		err = obj.Client.Rename(pathfrom, pathto)
	} else {
		_, errr := os.Stat(pathto)
		if errr == nil {
			if !obj.RemoveFile(pathto, isserver) {
				obj.Cred.ToLogs("Error deleting file - " + pathto)
				return false
			}
		}
		err = os.Rename(pathfrom, pathto)
	}
	if err != nil {
		obj.Cred.ToLogs(err.Error())
		if !obj.RemoveFile(pathfrom, isserver) {
			obj.Cred.ToLogs("Error deleting file - " + pathfrom)
			return false
		}
		return false
	}
	return true
}

func (obj *Sftp) CheckHash(path string, server bool) string {

	hfile := sha256.New()

	if server {
		file, _ := obj.Client.Open(path)
		io.Copy(hfile, file)
		closeFile(file)
	} else {
		file, _ := os.Open(path)
		io.Copy(hfile, file)
		closeFile(file)
	}
	return hex.EncodeToString(hfile.Sum(nil))
}

func (obj *Sftp) Disconnect() {
	defer obj.Client.Close()
	defer obj.Conn.Close()
}

type File struct {
	ServerSide  bool
	Fullname    string
	FullnameTmp string
	Name        string
	NameTmp     string
	Size        int64
	Hash        string
	AfterCopy   *FileRet
}

type FileRet struct {
	ServerSide  bool
	Fullname    string
	FullnameTmp string
	Name        string
	NameTmp     string
	Size        int64
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

type ScanObj interface {
	Init()
	New()

	Copy()
	Statistic()
	FillWorkers()
}

func (obj *Scan) Init() {
	obj.Server = new(Sftp)
	obj.S.Count = 0
	obj.S.Bad = 0
	obj.S.Errors = 0
	obj.S.Good = 0
	obj.Server.Cred = new(Cred)
	obj.Server.Cred.Init()
	if obj.Server.Init() {
		obj.Server.Connect()
	}
	//---init worker function
	obj.FuncRun = obj.CopyFile
	obj.FuncRes = obj.Statistic
	//---
}

func (obj *Scan) New() {
	obj.Init()
	obj.FilesOrigin = make(map[string]*File)
	re := regexp.MustCompile(obj.Server.Cred.FindMask)
	if obj.Server.SftpIsOrigin {
		w := obj.Server.Client.Walk(obj.Server.Cred.PathFrom)
		for w.Step() {
			if w.Err() != nil {
				continue
			}
			if !w.Stat().IsDir() {
				fileDir := strings.TrimSuffix(w.Path(), w.Stat().Name())
				if !obj.Server.Cred.FindSubfolder {
					if fileDir != obj.Server.Cred.PathFrom {
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
			f.Name = w.Stat().Name()
			f.Size = w.Stat().Size()
			f.Hash = obj.Server.CheckHash(w.Path(), true)
			f.ServerSide = true
			obj.FilesOrigin[w.Path()] = &f
		}
	} else {
		err := filepath.Walk(obj.Server.Cred.PathFrom, func(path string, info os.FileInfo, err error) error {
			fileDirDef := strings.Replace(obj.Server.Cred.PathFrom, `\`, `/`, -1)
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				fileDir := strings.Replace(strings.TrimSuffix(path, info.Name()), `\`, `/`, -1)
				if !obj.Server.Cred.FindSubfolder {
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
			f.Size = info.Size()
			f.Hash = obj.Server.CheckHash(path, false)
			f.ServerSide = false
			obj.FilesOrigin[path] = &f
			return nil
		})
		if err != nil {
			obj.Server.Cred.ToLogs(err.Error())
			panic(err)
		}
	}
}

func (obj *Scan) CopyFile(ff interface{}) bool {
	f := ff.(*File)
	var input []byte
	var err error
	if obj.Server.SftpIsOrigin {
		file, err := obj.Server.Client.Open(f.Fullname)
		if err != nil {
			obj.Server.Cred.ToLogs(err.Error())
		}
		scanner := bufio.NewReader(file)
		input, err = ioutil.ReadAll(scanner)
		if err != nil {
			obj.Server.Cred.ToLogs(err.Error())
		}
	} else {
		input, err = ioutil.ReadFile(f.Fullname)
		if err != nil {
			obj.Server.Cred.ToLogs(err.Error())
		}
	}
	nn := addTimeStr(f.Name, obj.Server.Cred.TimeStamp)
	if obj.Server.SftpIsDest {
		obj.Server.Client.MkdirAll(obj.Server.Cred.PathTo + "/")
		//file, _ := obj.Server.Client.Create(obj.Server.Cred.PathTo + "/" + addTimeStr(f.Name, obj.Server.Cred.TimeStamp))
		file, err := obj.Server.Client.Create(obj.Server.Cred.PathTo + "/" + srand(20, 20, true))
		if err != nil {
			obj.Server.Cred.ToLogs(err.Error())
			obj.S.Bad++
			return false
		}
		_, err = file.Write(input)
		if err != nil {
			obj.Server.Cred.ToLogs(err.Error())
			obj.S.Bad++
			return false
		} else {
			var nf FileRet
			nf_stet, _ := file.Stat()
			nf.Size = nf_stet.Size()
			nf.NameTmp = nf_stet.Name()
			nf.Name = nn
			nf.FullnameTmp = obj.Server.Cred.PathTo + "/" + nf_stet.Name()
			nf.Fullname = obj.Server.Cred.PathTo + "/" + nn
			nf.ServerSide = true
			nf.Hash = obj.Server.CheckHash(obj.Server.Cred.PathTo+"/"+nf_stet.Name(), true)
			f.AfterCopy = &nf
		}
		closeFile(file)
	} else {
		//file, _ := os.Create(obj.Server.Cred.PathTo + "/" + addTimeStr(f.Name, obj.Server.Cred.TimeStamp))
		os.MkdirAll(obj.Server.Cred.PathTo+"/", 755)
		file, err := os.Create(obj.Server.Cred.PathTo + "/" + srand(20, 20, true))
		if err != nil {
			obj.Server.Cred.ToLogs(err.Error())
			obj.S.Bad++
			return false
		}
		_, err = file.Write(input)
		//err = ioutil.WriteFile(obj.Server.Cred.PathTo+"/"+addTimeStr(f.Name, obj.Server.Cred.TimeStamp), input, 0644)
		if err != nil {
			obj.Server.Cred.ToLogs(err.Error())
			obj.S.Bad++
			return false
		} else {
			var nf FileRet
			nf_stet, _ := file.Stat()
			nf.Size = nf_stet.Size()
			nf.NameTmp = nf_stet.Name()
			nf.Name = nn
			nf.FullnameTmp = obj.Server.Cred.PathTo + "/" + nf_stet.Name()
			nf.Fullname = obj.Server.Cred.PathTo + "/" + nn
			nf.ServerSide = false
			nf.Hash = obj.Server.CheckHash(obj.Server.Cred.PathTo+"/"+nf_stet.Name(), false)
			f.AfterCopy = &nf
		}
		closeFile(file)
	}
	if f.Hash == f.AfterCopy.Hash && obj.Server.Cred.Move && f.Size == f.AfterCopy.Size {
		if obj.Server.RenameFile(f.AfterCopy.FullnameTmp, f.AfterCopy.Fullname, obj.Server.SftpIsDest) {
			if !obj.Server.RemoveFile(f.Fullname, f.ServerSide) {
				obj.Server.Cred.ToLogs("Error deleting file - " + f.Fullname)
				obj.S.Bad++
				return false
			}
			return true
		}
	}
	if f.Hash == f.AfterCopy.Hash && f.Size == f.AfterCopy.Size {
		if obj.Server.RenameFile(f.AfterCopy.FullnameTmp, f.AfterCopy.Fullname, obj.Server.SftpIsDest) {
			return true
		}
	}
	obj.S.Bad++
	return false
}

func (obj *Scan) Statistic(res_ interface{}) {
	result := res_.(Result)
	if obj.Server.Cred.Debug {
		obj.Server.Cred.ToLogs(result.job.element.(*File).Name + "->" + result.job.element.(*File).AfterCopy.Name + "[" + ToStr(result.job.element.(*File).Hash == result.job.element.(*File).AfterCopy.Hash) + "]")
	}
	obj.S.Count++
	if result.job.element.(*File).Hash == result.job.element.(*File).AfterCopy.Hash {
		obj.S.Good++
	} else {
		obj.S.Bad++
	}
}

func (obj *Scan) FillWorkers() map[string]*File {
	return obj.FilesOrigin
}

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

type FabricWorkersObj interface {
	init()
	worker()
	fillWorkers(frun, fres, interface{})
	createWorkerPool()
	result()
	end()
}

func (obj *FabricWorkers) init() {
	obj.Jobs = make(chan Job, 4)
	obj.Results = make(chan Result, 4)
	var wg sync.WaitGroup
	obj.Wg = &wg
	obj.Done = make(chan bool)
}

func (obj *FabricWorkers) end() {
	<-obj.Done
}

func (obj *FabricWorkers) worker() {
	for job := range obj.Jobs {
		output := Result{job, job.id(job.element)}
		obj.Results <- output
	}
	obj.Wg.Done()
}

func (obj *FabricWorkers) createWorkerPool() {
	for i := 0; i < runtime.NumCPU(); i++ {
		obj.Wg.Add(1)
		go obj.worker()
	}
	obj.Wg.Wait()
	close(obj.Results)
}

func (obj *FabricWorkers) fillWorkers(run frun, res fres, elements interface{}) {
	if reflect.ValueOf(elements).Kind() == reflect.Map {
		v := reflect.ValueOf(elements).MapRange()
		for v.Next() {
			f := v.Value()
			job := Job{run, res, f.Interface()}
			obj.Jobs <- job
		}
	}
	close(obj.Jobs)
}

func (obj *FabricWorkers) result() {
	for result := range obj.Results {
		result.job.idr(result)
	}
	obj.Done <- true
}

func (obj *Scan) Copy() {
	work := new(FabricWorkers)
	work.startTime = time.Now()
	work.init()
	go work.fillWorkers(obj.FuncRun, obj.FuncRes, obj.FilesOrigin)
	go work.result()
	go work.createWorkerPool()
	work.end()
	work.endTime = time.Now()
	obj.Server.Cred.ToLogs("Total time " + ToStr(work.endTime.Sub(work.startTime).String()) + "")
	obj.Server.Cred.ToLogs("Total Count: " + ToStr(obj.S.Count) + "")
	obj.Server.Cred.ToLogs("Count good: " + ToStr(obj.S.Good) + "")
	obj.Server.Cred.ToLogs("Count bad: " + ToStr(obj.S.Bad) + "")
	//obj.Server.Cred.ToLogs("If bad and good > Total => exist eqval file in destination folder")
	obj.Server.Cred.SaveLogs()
}

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

var p = fmt.Println

func separate(text string, symbol string) (string, string) {
	if strings.Contains(text, symbol) {
		return IndexArray(0, strings.Split(text, symbol)).(string), IndexArray(1, strings.Split(text, symbol)).(string) //bug
	} else {
		return "", text
	}
}

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

func init() {
	/*run settings*/
	runtime.GOMAXPROCS(runtime.NumCPU())
	runtime.LockOSThread()
	runtime.Gosched()
	rand.Seed(time.Now().UTC().UnixNano())
	/*------------*/
}

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

func main() {
	scan := new(Scan)
	scan.New()
	scan.Copy()
	//scan.Statistic()

}
