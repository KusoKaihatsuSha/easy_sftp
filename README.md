# Easy SFTP

A program by console interaction with graceful sftp

Usage:

  `-from string`
  
  `values: local or sftp path. If value is sftp path use prefix serversftp@/somepath`
  
  `-to string`
  
  `values: local or sftp path. If value is sftp path use prefix serversftp@/somepath`
  
  `-logs string`
  
  `values: path to folder with logs.  If value is empty => logs off`
  
  `-mask string`
  
  `values: regexp mask.  If value is empty select all files => .* (default ".*")`
  
  `-u string`
  
  `values: exist user sftp login. If value is empty => user (default "user")`
  
  `-p string`
  
  `values: exist user sftp pass. If value is empty => password (default "password")`
  
  `-port string`
  
  `values: usage port sftp. If value is empty => 22 (default "22")`
  
  `-sf boolean`
  
  `values: true or false for find in subfolder.  If value is empty => false (default "false")`
  
  `-ts boolean`
  
  `values: true or false for add suffix timestamp.  If value is empty => false (default "false")`
  
  `-m boolean`
  
  `values: true or false for move files.  If value is empty => false (default "false")`
  
  `-debug boolean`
  
  `values: true or false for more logs.  If value is empty => false (default "false")`
