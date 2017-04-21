# ethereum-presale-cracker
A tool for guessing passwords on Ethereum presale wallets

## Requirements

* Python 3
* Pycrypto (`pip install pycrypto`)
* GNU Parallel (recommended) (`sudo apt-get install parallel`)

## How to use

    # Single-threaded:
    cat passwords.txt | python ethcrack.py wallet.json
    # Parallel:
    parallel 'cat {} | python ethcrack.py wallet.json' ::: path/to/password/files_*.txt
    # Less verbose parallel:
    parallel 'cat {} | python ethcrack.py wallet.json' ::: path/to/password/files_*.txt | grep 'Found password:'
