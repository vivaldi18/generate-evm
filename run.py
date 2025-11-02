#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from eth_account import Account
from mnemonic import Mnemonic

# RPC ETH MAINNET
RPC_URL = "https://bold-fragrant-film.quiknode.pro/70587a09034b67ef8497e2022bde1d520e2feebe/"

# Lazy import web3
try:
    from web3 import Web3
except Exception:
    Web3 = None

# ---------- file helper ----------
def ensure_file_mode(path):
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)

def open_append_secure(path):
    ensure_file_mode(path)
    return open(path, "a", encoding="utf-8")

def read_existing_addresses(path):
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        lines = [l.strip().split(",")[0].strip() for l in f.readlines() if l.strip()]
    return set([l.lower() for l in lines])

# ---------- web3 helpers ----------
def init_web3():
    if Web3 is None:
        return None
    try:
        w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 10}))
        return w3
    except Exception:
        return None

def get_balance_w3(w3, address):
    try:
        bal = w3.eth.get_balance(address)
        return int(bal)
    except Exception:
        return None

def format_eth_balance(wei_val):
    try:
        if wei_val is None:
            return "0.0"
        if Web3:
            eth = Web3.fromWei(wei_val, "ether")
            s = f"{eth:.18f}"
            s = s.rstrip('0').rstrip('.') if '.' in s else s
            return s
        else:
            eth = int(wei_val) / 1e18
            s = f"{eth:.18f}"
            s = s.rstrip('0').rstrip('.') if '.' in s else s
            return s
    except Exception:
        return "0.0"

# ---------- main ----------
def main():
    print("=== Wallet Generator (unique-only, save funded to balance.txt) ===")
    try:
        raw = input("Masukkan jumlah wallet yang ingin dibuat (unik): ").strip()
        if not raw.isdigit():
            raise ValueError("Input harus berupa angka bulat >= 1")
        num_new = int(raw)
        if num_new < 1:
            raise ValueError("Jumlah minimal 1")
    except Exception as e:
        print(f"Input tidak valid: {e}")
        sys.exit(1)

    # file paths
    fn_phrase = "phrase.txt"
    fn_priv   = "privatekey.txt"
    fn_addr   = "address.txt"
    fn_bal    = "balance.txt"   # baru: hanya address yang ada saldo

    existing = read_existing_addresses(fn_addr)
    if existing:
        print(f"Terbaca {len(existing)} address di riwayat.")

    try:
        f_phrase = open_append_secure(fn_phrase)
        f_priv   = open_append_secure(fn_priv)
        f_addr   = open_append_secure(fn_addr)
        f_bal    = open_append_secure(fn_bal)
    except Exception as e:
        print(f"Gagal membuka file output: {e}")
        sys.exit(1)

    w3 = init_web3()
    if w3 is None:
        print("Catatan: tidak bisa konek RPC. Saldo akan tampil 0.0.")

    try:
        Account.enable_unaudited_hdwallet_features()
        mnemo = Mnemonic("english")

        created = 0
        attempts = 0
        MAX_TOTAL_ATTEMPTS = max(1000, num_new * 1000)

        while created < num_new and attempts < MAX_TOTAL_ATTEMPTS:
            attempts += 1
            mnemonic_phrase = mnemo.generate(strength=128)
            wallet = Account.from_mnemonic(mnemonic_phrase)
            private_key = wallet.key.hex()
            address = wallet.address
            address_lc = address.lower()

            if address_lc in existing:
                print(f"skip (sudah ada): {address}")
                continue

            # tulis ke file biasa
            f_phrase.write(mnemonic_phrase + "\n")
            f_priv.write(private_key + "\n")
            f_addr.write(address + "\n")
            f_phrase.flush(); f_priv.flush(); f_addr.flush()

            existing.add(address_lc)
            created += 1

            # cek saldo
            wei_bal = None
            if w3 is not None:
                try:
                    wei_bal = get_balance_w3(w3, address)
                except Exception:
                    wei_bal = None
            balance_str = format_eth_balance(wei_bal)

            # jika ada saldo > 0 ? simpan ke balance.txt
            try:
                if wei_bal and wei_bal > 0:
                    f_bal.write(f"{address},{private_key},{mnemonic_phrase},{balance_str} ETH\n")
                    f_bal.flush()
                    print(f"[{created}/{num_new}] {address}  (balance: {balance_str} ETH)  <-- tersimpan di balance.txt")
                else:
                    print(f"[{created}/{num_new}] {address}  (balance: {balance_str} ETH)")
            except Exception:
                print(f"[{created}/{num_new}] {address}  (balance: {balance_str} ETH) (gagal menulis balance.txt)")

        if created < num_new:
            print(f"\nHanya berhasil generate {created}/{num_new} wallet unik.")
        else:
            print("\nSelesai membuat wallet baru (unik).")

    finally:
        for h in (f_phrase, f_priv, f_addr, f_bal):
            try: h.close()
            except: pass

    print(f"- Mnemonic: {fn_phrase}")
    print(f"- Private keys: {fn_priv}")
    print(f"- Addresses: {fn_addr}")
    print(f"- Funded wallets: {fn_bal}")
    print("\nPERINGATAN: Simpan file-file ini secara privat. Siapapun yang punya mnemonic/private key bisa menguasai asetmu.")

if __name__ == "__main__":
    main()
