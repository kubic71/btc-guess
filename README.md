# BTC guess
BTC guess is simple python utility that samples randomly 256-bit private keys a tries to find a one with positive balance.  

## Instalation
1) Install Python 3.
2) Use the package manager [pip](https://pip.pypa.io/en/stable/) to install all the requirements
```bash
pip install -r requirements.txt

```

## Usage 

### Run indefinitely
```bash
python btc_guess.py

```

### Key-range specification
Following would sample keys only from `0x1` to `0xFF`
```bash
python btc_guess.py --min-key=1 --max-key=FF
```


### Number of sampled keys
`--n` option can be specified. Following would try only 1 random key and then terminate.
```bash
python btc_guess.py --n=1
```


## Logging keys
If by some miracle you are able to find private key with some Bitcoins in it, this private key along with other information is logged to `keys_with_balance.txt`
