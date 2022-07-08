[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![godoc](https://godoc.org/github.com/KusoKaihatsuSha/easy_sftp?status.svg)](https://godoc.org/github.com/KusoKaihatsuSha/easy_sftp) [![Go Report Card](https://goreportcard.com/badge/github.com/KusoKaihatsuSha/easy_sftp)](https://goreportcard.com/report/github.com/KusoKaihatsuSha/easy_sftp)

# SFTP CLI client

> App for synchronized data between servers using CLI through SFTP client.

### Accessible flags:

  `-from string`

  Local or sftp path. If value is sftp path use prefix serversftp@/somepath

  `-to string`

  Local or sftp path. If value is sftp path use prefix serversftp@/somepath

  `-logs string`

  Path to folder with logs.  If value is empty => logs off

  `-mask string`

  RegExp mask.  If value is empty select all files => .* (default ".*")

  `-u string`

  Exist user sftp login. If value is empty => user (default "user")

  `-p string`

  Exist user sftp pass. If value is empty => password (default "password")

  `-port string`

  Usage port sftp. If value is empty => 22 (default "22")

  `-sf boolean`

  True or false for find in subfolder.  If value is empty => false (default "false")

  `-ts boolean`

  True or false for add suffix timestamp.  If value is empty => false (default "false")

  `-m boolean`

  True or false for move files.  If value is empty => false (default "false")

  `-debug boolean`

  True or false for more logs.  If value is empty => false (default "false")
