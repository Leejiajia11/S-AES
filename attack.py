import tkinter as tk
from tkinter import messagebox

# S-AES常量
S_BOX = [
    [0x9, 0x4, 0xa, 0xb],
    [0xd, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xc, 0xe, 0xf, 0x7]
]

INV_S_BOX = [[S_BOX[j][i] for i in range(4)] for j in range(4)]

GF_MUL_TABLE = [
    [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
    [0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD],
    [0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2],
    [0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9],
    [0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3, 0x6],
    [0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4],
    [0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB],
    [0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1],
    [0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE],
    [0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1, 0xB, 0x6, 0xC],
    [0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3],
    [0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2, 0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8],
    [0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7],
    [0x0, 0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5],
    [0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC, 0x3, 0x8, 0x7, 0x5, 0xA]
]

RCON = [0x01, 0x02]


def sub_nib(nibble):
    row = (nibble >> 2) & 0x3
    col = nibble & 0x3
    return S_BOX[row][col]


def inv_sub_nib(nibble):
    row = (nibble >> 2) & 0x3
    col = nibble & 0x3
    return INV_S_BOX[row][col]


def rot_word(word):
    return (word >> 8) | ((word & 0xFF) << 8)


def key_expansion(key):
    w = [key]
    for i in range(2):
        temp = rot_word(w[-1])
        temp = (sub_nib(temp >> 8) << 8) | sub_nib(temp & 0xFF)
        temp ^= RCON[i]
        w.append(w[-1] ^ temp)
    return w


def add_round_key(state, round_key):
    return state ^ round_key


def shift_rows(state):
    return ((state & 0xF000) & 0xF000) | ((state & 0x0F00) << 4) | ((state & 0x00F0) >> 4) | ((state & 0x000F) << 8)


def inv_shift_rows(state):
    return ((state & 0xF000) & 0xF000) | ((state & 0x0F00) >> 4) | ((state & 0x00F0) << 4) | ((state & 0x000F) >> 8)


def mix_columns(state):
    s0 = (state >> 12) & 0xF
    s1 = (state >> 8) & 0xF
    s2 = (state >> 4) & 0xF
    s3 = state & 0xF
    new_s0 = GF_MUL_TABLE[1][s0] ^ GF_MUL_TABLE[4][s1]
    new_s1 = GF_MUL_TABLE[1][s1] ^ GF_MUL_TABLE[4][s0]
    new_s2 = GF_MUL_TABLE[1][s2] ^ GF_MUL_TABLE[4][s3]
    new_s3 = GF_MUL_TABLE[1][s3] ^ GF_MUL_TABLE[4][s2]
    return (new_s0 << 12) | (new_s1 << 8) | (new_s2 << 4) | new_s3


def inv_mix_columns(state):
    s0 = (state >> 12) & 0xF
    s1 = (state >> 8) & 0xF
    s2 = (state >> 4) & 0xF
    s3 = state & 0xF
    new_s0 = GF_MUL_TABLE[9][s0] ^ GF_MUL_TABLE[2][s1]
    new_s1 = GF_MUL_TABLE[9][s1] ^ GF_MUL_TABLE[2][s0]
    new_s2 = GF_MUL_TABLE[9][s2] ^ GF_MUL_TABLE[2][s3]
    new_s3 = GF_MUL_TABLE[9][s3] ^ GF_MUL_TABLE[2][s2]
    return (new_s0 << 12) | (new_s1 << 8) | (new_s2 << 4) | new_s3


def encrypt(plaintext, key):
    w = key_expansion(key)
    state = add_round_key(plaintext, w[0])
    for i in range(1, 2):
        state = (sub_nib(state >> 8) << 8) | sub_nib(state & 0xFF)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, w[i])
    state = (sub_nib(state >> 8) << 8) | sub_nib(state & 0xFF)
    state = shift_rows(state)
    state = add_round_key(state, w[-1])
    return state


def decrypt(ciphertext, key):
    w = key_expansion(key)
    state = add_round_key(ciphertext, w[-1])
    for i in reversed(range(1, 2)):
        state = inv_shift_rows(state)
        state = (inv_sub_nib(state >> 8) << 8) | inv_sub_nib(state & 0xFF)
        state = add_round_key(state, w[i])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = (inv_sub_nib(state >> 8) << 8) | inv_sub_nib(state & 0xFF)
    state = add_round_key(state, w[0])
    return state


def string_to_blocks(s):
    return [int(s[i:i+16], 2) for i in range(0, len(s), 16)]


def blocks_to_string(blocks):
    return ''.join(format(block, '016b') for block in blocks)


def encrypt_string(plaintext, key):
    blocks = string_to_blocks(plaintext)
    encrypted_blocks = [encrypt(block, key) for block in blocks]
    return blocks_to_string(encrypted_blocks)


def decrypt_string(ciphertext, key):
    blocks = string_to_blocks(ciphertext)
    decrypted_blocks = [decrypt(block, key) for block in blocks]
    return blocks_to_string(decrypted_blocks)


class SAESApp:
    def __init__(self, master):
        self.master = master
        master.title("Simplified AES Encryption/Decryption")

        self.plaintext_label = tk.Label(master, text="Plaintext (16 bits in binary):")
        self.plaintext_label.pack()
        self.plaintext_entry = tk.Entry(master, width=50)
        self.plaintext_entry.pack()

        self.key_label = tk.Label(master, text="Key (16 bits in binary):")
        self.key_label.pack()
        self.key_entry = tk.Entry(master, width=50)
        self.key_entry.pack()

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack()

        self.result_label = tk.Label(master, text="")
        self.result_label.pack()

    def encrypt(self):
        plaintext = self.plaintext_entry.get()
        key = int(self.key_entry.get(), 2)
        try:
            if len(plaintext) != 16:
                raise ValueError("Plaintext must be 16 bits in binary")
            plaintext = int(plaintext, 2)
            ciphertext = encrypt(plaintext, key)
            self.result_label.config(text=f"Ciphertext: {format(ciphertext, '016b')}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        ciphertext = self.plaintext_entry.get()
        key = int(self.key_entry.get(), 2)
        try:
            if len(ciphertext) != 16:
                raise ValueError("Ciphertext must be 16 bits in binary")
            ciphertext = int(ciphertext, 2)
            plaintext = decrypt(ciphertext, key)
            self.result_label.config(text=f"Plaintext: {format(plaintext, '016b')}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = SAESApp(root)
    root.mainloop()

# 输入明文和密文对
plain1 = int(input("请输入明文1（16位二进制）："), 2)
cipher1 = int(input("请输入密文1（16位二进制）："), 2)
plain2 = int(input("请输入明文2（16位二进制）："), 2)
cipher2 = int(input("请输入密文2（16位二进制）："), 2)

# 创建一个字典来存储中间状态
forward_states = {}
backward_states = {}

# 从明文到中间状态
for key in range(65536):
    w = key_expansion(key)
    state = add_round_key(plain1, w[0])
    state = (sub_nib(state >> 8) << 8) | sub_nib(state & 0xFF)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, w[1])
    forward_states[state] = key

# 从密文到中间状态
for key in range(65536):
    w = key_expansion(key)
    state = add_round_key(cipher1, w[-1])
    state = inv_shift_rows(state)
    state = (inv_sub_nib(state >> 8) << 8) | inv_sub_nib(state & 0xFF)
    state = add_round_key(state, w[1])
    state = inv_mix_columns(state)
    backward_states[state] = key

# 查找匹配的中间状态
found_keys = []
for state in forward_states:
    if state in backward_states:
        found_keys.append((forward_states[state], backward_states[state]))

# 输出所有满足条件的密钥
if found_keys:
    print("找到的密钥对：")
    for key1, key2 in found_keys:
        print(f"Key1: {format(key1, '016b')}, Key2: {format(key2, '016b')}")
else:
    print("没有找到匹配的密钥对。")