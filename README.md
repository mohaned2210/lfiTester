lfi and ssrf Tester for multiple urls parameter.

usage
```
python3 ssrfLfiScanner.py --urls gf_patren/lfiaSsrf.txt --lfi --vpn  -d 500 --timeout 3 -t 50 --debug
```
or
```
python3 ssrfLfiScanner.py --urls gf_patren/lfiaSsrf.txt --lfi --ssrf --vpn  -d 500 --timeout 3 -t 50 
```

red color means found vulnerable param.

note you must have a vpn to use this script becuse will change the ip every 30 second.
