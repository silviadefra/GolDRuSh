# Experiments on 10 libraries


## Libraries

|Lib | Version | Size | Instructions|
|:---------------- | :------: | ----: | ----: |
|libcurl |4.8.0|3,9MB| 200172|
| libgsl |25.1.0 |8,1MB|785355|
| liblouis | 20.0.19|443kB|49547|
| libpng |16.44.0 |651kB|56844|
| libusb | 0.4.0|317kB|22836|
| libwebp | 7.1.9|2MB|168881|
| libxml2 |2.13.0 |5MB|239372|
| libxslt |1.1.42 |763kB|60931|
| libssl | 3 |3,9MB|236754|
| zlib |1.3 |236kB|22781|

## Running GolDRuSh

For our tool we tested the complete set of rules that we designed `rules/rules.txt`.

To execute the experiments we put all the executables in a directory (`targets`) and used the `run_goldrush.sh` script.

```bash
./run_goldrush.sh <volume_path>
```

Note that this script requires our `Dockerfile` and `requirements.txt`.


GolDRuSh autonomously detected a 0-day buffer overflow vulnerability [CVE-2024-50610](https://www.cve.org/CVERecord?id=CVE-2024-50610) on libgsl (more details in the folder `vulnerabilities`).