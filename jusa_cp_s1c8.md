here is one: 
*  Download the file
````
$ wget https://cryptopals.com/static/challenge-data/8.txt
````
*  Magic
````
$ grep -n -oP  '.{0,32}' 8.txt | sort | uniq -c | grep -v '^[^0-9]*1'
````

* The line `133` has the ECB ciphertext
```
$ grep 08649af70dc06f4fd5d2d69c744cd283 datafile.txt
```
