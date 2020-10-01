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
	. "github.com/ulvham/helper"
	"golang.org/x/crypto/ssh"

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
	Salt          string
}

type CredObj interface {
	Init()
	ToLogs(string)
	SaveLogs()
}

func (obj *Cred) Init() {
	obj.Salt = srand(10, 10, true)
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
	obj.Logs = append(obj.Logs, obj.Salt+":"+text)
	p(text)
}

func (obj *Cred) SaveLogs() {
	if strings.Trim(obj.PathLogs, "") != "" {
		f, _ := os.OpenFile(obj.PathLogs+"logs"+time.Now().Format("_2006_01")+".txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
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
		obj.Cred.ToLogs(err.Error())
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
		obj.Cred.ToLogs(err.Error())
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
			//obj.Cred.ToLogs(err.Error())
			return false
		}
	} else {
		err := os.Remove(path)
		if err != nil {
			//obj.Cred.ToLogs(err.Error())
			return false
		}
	}
	return true
}

func (obj *Sftp) RenameFile(pathfrom string, pathto string, isserver bool) bool {

	var err error
	if isserver {
		err = obj.Client.Rename(pathfrom, pathto)
	} else {
		err = os.Rename(pathfrom, pathto)
	}
	if err != nil {
		obj.Cred.ToLogs(err.Error())
		return false
	}
	return true
}

func (obj *Sftp) CheckFile(path string, server bool) bool {
	if server {
		_, errr := obj.Client.Stat(path)
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

func (obj *Sftp) CheckHash(path string, server bool) string {

	hfile := sha256.New()

	if server {
		file, _ := obj.Client.OpenFile(path, os.O_RDONLY)
		if obj.CheckFile(path, server) {
			io.Copy(hfile, file)
			closeFile(file)
		}

	} else {
		file, _ := os.OpenFile(path, os.O_RDONLY, 0664)
		//, os.O_WRONLY|os.O_CREATE|os.O_TRUNC
		if obj.CheckFile(path, server) {
			io.Copy(hfile, file)
			closeFile(file)
		}
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

func (obj *Scan) FileLockStat() (bool, time.Time) {
	str1 := "~~~!!!d!!!~~~"
	str2 := "~~~!!!o!!!~~~"
	if obj.Server.SftpIsDest {
		f, errr := obj.Server.Client.Stat(obj.Server.Cred.PathTo + str1)
		if errr == nil {
			return true, f.ModTime()
		}
	} else {
		f, errr := os.Stat(obj.Server.Cred.PathTo + str1)
		if errr == nil {
			return true, f.ModTime()
		}
	}

	if obj.Server.SftpIsOrigin {
		f, errr := obj.Server.Client.Stat(obj.Server.Cred.PathFrom + str2)
		if errr == nil {
			return true, f.ModTime()
		}
	} else {
		f, errr := os.Stat(obj.Server.Cred.PathFrom + str2)
		if errr == nil {
			return true, f.ModTime()
		}
	}
	return false, time.Now()
}

func (obj *Scan) Lock() {
	for {
		if fls, t := obj.FileLockStat(); fls {
			p(time.Since(t).Round(1*time.Second).Seconds(), time.Since(t).Round(1*time.Second).Seconds() > 3600)
			if time.Since(t).Round(1*time.Second).Seconds() > 3600 {
				obj.Unlock()
			}
		} else {
			break
		}
		time.Sleep(5 * time.Second)
	}

	str1 := "~~~!!!d!!!~~~"
	str2 := "~~~!!!o!!!~~~"
	if fls, _ := obj.FileLockStat(); !fls {
		if obj.Server.SftpIsDest {
			file, err := obj.Server.Client.Create(obj.Server.Cred.PathTo + str1)
			defer file.Close()
			if err != nil {
				p(err)
			}

		} else {
			file, err := os.Create(obj.Server.Cred.PathTo + str1)
			//file, err := os.OpenFile(obj.Server.Cred.PathTo+str1, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
			defer file.Close()
			if err != nil {
				p(err)
			}
		}
		if obj.Server.SftpIsOrigin {
			file, err := obj.Server.Client.Create(obj.Server.Cred.PathFrom + str2)
			defer file.Close()
			if err != nil {
				p(err)
			}
		} else {
			file, err := os.Create(obj.Server.Cred.PathFrom + str2)
			//file, err := os.OpenFile(obj.Server.Cred.PathTo+str1, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
			defer file.Close()
			if err != nil {
				p(err)
			}
		}
	}
}

func (obj *Scan) Unlock() {
	str1 := "~~~!!!d!!!~~~"
	str2 := "~~~!!!o!!!~~~"
	if fls, _ := obj.FileLockStat(); fls {
		if obj.Server.SftpIsDest {
			obj.Server.RemoveFile(obj.Server.Cred.PathTo+str1, obj.Server.SftpIsDest)
		} else {
			obj.Server.RemoveFile(obj.Server.Cred.PathTo+str1, obj.Server.SftpIsDest)
		}
		if obj.Server.SftpIsOrigin {
			obj.Server.RemoveFile(obj.Server.Cred.PathFrom+str2, obj.Server.SftpIsOrigin)
		} else {
			obj.Server.RemoveFile(obj.Server.Cred.PathFrom+str2, obj.Server.SftpIsOrigin)
		}
	}
}

func (obj *Scan) New() {

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
			f.DateMod = w.Stat().ModTime()
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
			f.DateMod = info.ModTime()
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

	if obj.Server.CheckFile(obj.Server.Cred.PathFrom+f.Name, obj.Server.SftpIsOrigin) {
		if obj.Coping(f) {
			return true
		}
	}
	return false
}

func (obj *Scan) Coping(f *File) bool {
	var input []byte
	var err error
	if obj.Server.SftpIsOrigin {
		file, err := obj.Server.Client.Open(f.Fullname)
		if err != nil {
			//obj.Server.Cred.ToLogs(err.Error())
			//obj.S.Bad++
			return false
		}
		scanner := bufio.NewReader(file)
		input, err = ioutil.ReadAll(scanner)
		if err != nil {
			//obj.Server.Cred.ToLogs(err.Error())
			//obj.S.Bad++
			return false
		}
	} else {
		input, err = ioutil.ReadFile(f.Fullname)
		if err != nil {
			//obj.Server.Cred.ToLogs(err.Error())
			//obj.S.Bad++
			return false
		}
	}
	nn := addTimeStr(f.Name, obj.Server.Cred.TimeStamp)
	if obj.Server.SftpIsDest {
		obj.Server.Client.MkdirAll(obj.Server.Cred.PathTo + "/")
		//file, _ := obj.Server.Client.Create(obj.Server.Cred.PathTo + "/" + addTimeStr(f.Name, obj.Server.Cred.TimeStamp))
		//file, err := obj.Server.Client.Create(obj.Server.Cred.PathTo + "/" + srand(20, 20, true))
		//file, err := obj.Server.Client.Create(obj.Server.Cred.PathTo + "/" + nn + "__" + srand(20, 20, true))
		//file, err := obj.Server.Client.Create(obj.Server.Cred.PathTo + "/" + nn)
		file, err := obj.Server.Client.OpenFile(obj.Server.Cred.PathTo+"/"+nn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			//obj.Server.Cred.ToLogs(err.Error())
			//obj.S.Bad++
			return false
		}
		_, err = file.Write(input)
		if err != nil {
			//obj.Server.Cred.ToLogs(err.Error())
			//obj.S.Bad++
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

			err = obj.Server.Client.Chtimes(obj.Server.Cred.PathTo+"/"+nf_stet.Name(), f.DateMod, f.DateMod)
			if err != nil {
				//	fmt.Println(err)
			}
		}
		closeFile(file)

	} else {
		//file, _ := os.Create(obj.Server.Cred.PathTo + "/" + addTimeStr(f.Name, obj.Server.Cred.TimeStamp))
		os.MkdirAll(obj.Server.Cred.PathTo+"/", 755)
		//file, err := os.Create(obj.Server.Cred.PathTo + "/" + srand(20, 20, true))
		//file, err := os.Create(obj.Server.Cred.PathTo + "/" + nn + "__" + srand(20, 20, true))
		//file, err := os.Create(obj.Server.Cred.PathTo + "/" + nn)
		file, err := os.OpenFile(obj.Server.Cred.PathTo+"/"+nn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
		if err != nil {
			//obj.Server.Cred.ToLogs(err.Error())
			//obj.S.Bad++
			return false
		}
		_, err = file.Write(input)
		//err = ioutil.WriteFile(obj.Server.Cred.PathTo+"/"+addTimeStr(f.Name, obj.Server.Cred.TimeStamp), input, 0644)
		if err != nil {
			//obj.Server.Cred.ToLogs(err.Error())
			//obj.S.Bad++
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

			err = os.Chtimes(obj.Server.Cred.PathTo+"/"+nf_stet.Name(), f.DateMod, f.DateMod)
			if err != nil {
				//obj.Server.Cred.ToLogs(err.Error())
			}
		}
		closeFile(file)

	}
	if f.Hash == f.AfterCopy.Hash && f.Size == f.AfterCopy.Size {
		return true
	}
	//obj.Server.Cred.ToLogs("[-]" + f.Name + "->" + f.AfterCopy.Name + "[" + ByteCountDecimal(f.AfterCopy.Size) + "/" + ByteCountDecimal(f.Size) + "]")
	return false
}

func (obj *Scan) Renaming(f *File) bool {
	if f.Hash == f.AfterCopy.Hash && f.Size == f.AfterCopy.Size {
		if obj.Server.RenameFile(f.AfterCopy.FullnameTmp, f.AfterCopy.Fullname, obj.Server.SftpIsDest) {
			return true
		}
	}
	obj.Server.Cred.ToLogs("Error Rename")
	return false
}

func (obj *Scan) Cleaning(f *File) (bool, string) {
	if f.Hash == f.AfterCopy.Hash && obj.Server.Cred.Move && f.Size == f.AfterCopy.Size {
		if !obj.Server.RemoveFile(f.Fullname, f.ServerSide) {
			return false, "Error deleting file"
		}
	}
	return true, ""
}

func (obj *Scan) RenamingError(f *File) bool {
	if f.Hash != f.AfterCopy.Hash || f.Size != f.AfterCopy.Size {
		if obj.Server.RenameFile(f.AfterCopy.FullnameTmp, f.AfterCopy.Fullname+"_error_", obj.Server.SftpIsDest) {
			return true
		}
	}
	obj.Server.Cred.ToLogs("Error Rename")
	return false
}

func (obj *Scan) Statistic(res_ interface{}) {
	result := res_.(Result)
	obj.S.Count++
	if result.job.element.(*File).AfterCopy != nil {
		if result.job.element.(*File).Hash == result.job.element.(*File).AfterCopy.Hash && result.job.element.(*File).Size == result.job.element.(*File).AfterCopy.Size {

			if val, add_ := obj.Cleaning(result.job.element.(*File)); val {
				obj.Server.Cred.ToLogs("[+]" + result.job.element.(*File).Name + "->" + result.job.element.(*File).AfterCopy.Name + "[" + ByteCountDecimal(result.job.element.(*File).AfterCopy.Size) + "/" + ByteCountDecimal(result.job.element.(*File).Size) + "]")
				obj.S.Good++
			} else {
				obj.Server.Cred.ToLogs("[-]" + result.job.element.(*File).Name + "->" + result.job.element.(*File).AfterCopy.Name + "[" + ByteCountDecimal(result.job.element.(*File).AfterCopy.Size) + "/" + ByteCountDecimal(result.job.element.(*File).Size) + "]" + add_)
				obj.S.Bad++
			}
		} else {
			obj.Server.Cred.ToLogs("[-]" + result.job.element.(*File).Name + "->" + result.job.element.(*File).AfterCopy.Name + "[" + ByteCountDecimal(result.job.element.(*File).AfterCopy.Size) + "/" + ByteCountDecimal(result.job.element.(*File).Size) + "]")
			obj.S.Bad++
		}
	} else {
		obj.Server.Cred.ToLogs("[-]" + result.job.element.(*File).Name + "->NULL " + "[" + " 0 /" + ByteCountDecimal(result.job.element.(*File).Size) + "]")
		obj.S.Bad++
	}
}

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
	obj.Server.Cred.ToLogs(">---------------------------------------->")
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
	obj.Server.Cred.ToLogs("<----------------------------------------<")
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
	scan.Init()

	//scan.Lock()
	scan.New()
	scan.Copy()
	//scan.Unlock()

	//scan.Server.Client.Wait()

	//scan.Statistic()

}
