# 

* `curl-format.txt`:
```
     time_namelookup:  %{time_namelookup}s\n 
        time_connect:  %{time_connect}s\n 
     time_appconnect:  %{time_appconnect}s\n 
    time_pretransfer:  %{time_pretransfer}s\n 
       time_redirect:  %{time_redirect}s\n 
  time_starttransfer:  %{time_starttransfer}s\n 
                     ----------\n 
          time_total:  %{time_total}s\n

```

* Typical Python(Flask) implementation's round-trip time as measured by cURL:

```
curl -w "@/tmp/curl-format.txt" -o /dev/null -s "http://127.0.0.1:91/health_check/"
     time_namelookup:  0.000148s
        time_connect:  0.000552s
     time_appconnect:  0.000000s
    time_pretransfer:  0.000727s
       time_redirect:  0.000000s
  time_starttransfer:  0.003608s
                     ----------
          time_total:  0.003773s
```

* Typical C(Onion) implementation's round-trip time as measured by cURL:

```
curl -w "@/tmp/curl-format.txt" -o /dev/null -s "http://127.0.0.1:4444/health_check/"
     time_namelookup:  0.000208s
        time_connect:  0.000753s
     time_appconnect:  0.000000s
    time_pretransfer:  0.001009s
       time_redirect:  0.000000s
  time_starttransfer:  0.001282s
                     ----------
          time_total:  0.001477s
```