import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os, sys, threading, re
from enum import Enum
from cryptography.hazmat.primitives.asymmetric import dsa, ed25519, rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.exceptions import InvalidSignature

# 添加当前目录到系统路径
#sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.ClassicalCrypto.affine import affine_encrypt,affine_decrypt
from src.ClassicalCrypto.matrix import matrix_encrypt,matrix_decrypt
from src.ClassicalCrypto.mono_sub import mono_sub_encrypt,mono_sub_decrypt
from src.ClassicalCrypto.vigenere import vigenere_encrypt,vigenere_decrypt
from src.ClassicalCrypto.railfence import railfence_encrypt,railfence_decrypt
from src.ClassicalCrypto.caesar import caesar_decrypt,caesar_encrypt
from src.SymmetricCrypto.tripledes import tripledes_encrypt_decrypt
from src.SymmetricCrypto.aes import aes_encrypt_decrypt
from src.SymmetricCrypto.sm4 import sm4_encrypt_decrypt
from src.SymmetricCrypto.des import des_encrypt_decrypt
from src.AsymmetricCrypto.rsa import rsa_key_gen,rsa_encrypt_str,rsa_decrypt_str
from src.AsymmetricCrypto.ECC import *
from src.HashCrypto.sha1 import sha1_hexdigest
def resource_path(relative_path):
    """获取资源路径，兼容 PyInstaller 打包环境"""
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)
class AppState(Enum):
    IDLE = 0
    PROCESSING = 1

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CipherSuite")
        self.root.geometry("1000x750")
        self.root.minsize(900,650)
        try:
            root.iconbitmap('assets/images/icon.ico')
        except Exception as e:
            print(1111)
            icon_path = resource_path("images/icon.png")
            img = tk.PhotoImage(file=icon_path)
            root.iconphoto(False, img)

        #sv_ttk.set_theme('dark')
        self.setup_theme()
        self.state = AppState.IDLE
        self.status_var = tk.StringVar(value="就绪")

        # 主框架
        main = ttk.Frame(root)
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # 标题栏
        header = ttk.Frame(main)
        header.pack(fill=tk.X, pady=(0,20))
        ttk.Label(header, text="CipherSuite", font=("Arial",15,"bold"), foreground="#4FC3F7").pack(side=tk.LEFT)
        ttk.Label(header, text="Shiyou Lin © 2025", font=("Segoe UI",9)).pack(side=tk.LEFT, padx=10)

        # 选项卡
        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.tabs = {}
        for name, creator in [
            ("古典密码", self.create_classical_ui),
            ("对称加密", self.create_block_ui),
            ("非对称加密", self.create_pubkey_ui),
            ("哈希函数", self.create_hash_ui),
            ("数字签名", self.create_signature_ui)
        ]:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=name)
            self.tabs[name] = {'frame':frame,'loaded':False,'creator':creator}
        self.notebook.bind('<<NotebookTabChanged>>', self.lazy_load_tab)
        self.lazy_load_tab()

        # 状态栏
        status = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_theme(self):
        style = ttk.Style()
        style.theme_use('clam')

        # 配置框架样式
        style.configure("Section.TLabelframe",
                        background="#f0f0f0",
                        bordercolor="#cccccc",
                        relief=tk.RAISED,
                        borderwidth=1)
        style.configure("Section.TLabelframe.Label",
                        background="#f0f0f0",
                        foreground="#333333",
                        font=("Segoe UI", 10, "bold"))

        # 配置按钮样式
        style.configure("TButton",
                        padding=6,
                        font=("Segoe UI", 10),
                        background="#e1e1e1")
        style.configure("Accent.TButton",
                        background="#4a86e8",
                        foreground="white")
        style.map("Accent.TButton",
                  background=[('active', '#3a76d8'), ('pressed', '#2a66c8')])

        # 配置标签样式
        style.configure("TLabel",
                        background="#f0f0f0",
                        font=("Segoe UI", 9))

        # 配置文本区域
        style.configure("TFrame", background="#f0f0f0")

    def lazy_load_tab(self, event=None):
        name = self.notebook.tab(self.notebook.select(), 'text')
        tab = self.tabs[name]
        if not tab['loaded']:
            tab['creator'](tab['frame'])
            tab['loaded'] = True
            self.status_var.set(f"已加载：{name}")

    def threaded(self, fn):
        if self.state==AppState.PROCESSING:
            messagebox.showinfo('处理中','请稍候')
            return
        self.state=AppState.PROCESSING
        self.status_var.set('处理中...')
        threading.Thread(target=self._run, args=(fn,), daemon=True).start()

    def _run(self, fn):
        try:
            fn()
        except Exception as e:
            self.root.after(0, lambda err=e: messagebox.showerror('错误', str(err)))
        finally:
            self.state = AppState.IDLE
            self.root.after(0, lambda: self.status_var.set('就绪'))

    def create_classical_ui(self, parent):
        """创建古典密码界面"""
        frame = ttk.LabelFrame(parent, text="古典密码算法", padding=15, style="Section.TLabelframe")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 算法选择
        algo_frame = ttk.Frame(frame)
        algo_frame.pack(fill=tk.X, pady=10)

        ttk.Label(algo_frame, text="选择算法:", font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=5)

        # 使用下拉选择框代替单选按钮
        self.classical_algo = tk.StringVar()
        algorithms = ["仿射密码", "凯撒密码", "维吉尼亚密码", "单表代换密码", "栅栏密码", "矩阵置换密码"]
        algo_combo = ttk.Combobox(
            algo_frame,
            textvariable=self.classical_algo,
            values=algorithms,
            state="readonly",
            width=20,
            font=("Segoe UI", 10)
        )
        algo_combo.current(0)
        algo_combo.pack(side=tk.LEFT, padx=5)

        # 输入输出框架
        io_frame = ttk.Frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # 输入区
        input_frame = ttk.LabelFrame(io_frame, text="输入", padding=10, style="Section.TLabelframe")
        input_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        ttk.Label(input_frame, text="明文/密文:", font=("Segoe UI", 9)).pack(anchor=tk.W)
        self.classical_input = scrolledtext.ScrolledText(
            input_frame,
            height=8,
            width=30,
            font=("Consolas", 10),
            padx=5,
            pady=5
        )
        self.classical_input.pack(fill=tk.BOTH, expand=True)

        ttk.Label(input_frame, text="密钥:", font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(10, 0))
        self.classical_key = ttk.Entry(
            input_frame,
            width=40,
            font=("Consolas", 10)
        )
        self.classical_key.pack(fill=tk.X, padx=5, pady=5)

        # 输出区
        output_frame = ttk.LabelFrame(io_frame, text="输出", padding=10, style="Section.TLabelframe")
        output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

        ttk.Label(output_frame, text="结果:", font=("Segoe UI", 9)).pack(anchor=tk.W)
        self.classical_output = scrolledtext.ScrolledText(
            output_frame,
            height=8,
            width=30,
            font=("Consolas", 10),
            padx=5,
            pady=5
        )
        self.classical_output.pack(fill=tk.BOTH, expand=True)
        self.classical_output.config(state=tk.DISABLED)

        # 按钮区
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(
            btn_frame,
            text="加密",
            command=lambda: self.threaded(self.classical_encrypt),
            style="Accent.TButton",
            width=10
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="解密",
            command=lambda: self.threaded(self.classical_decrypt),
            width=10
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="清空",
            command=self.clear_classical,
            width=10
        ).pack(side=tk.RIGHT, padx=5)

        ttk.Button(
            btn_frame,
            text="将结果转移到输入",
            command=self.output_to_input_classical,  # 指向你的交换函数
            width=15
        ).pack(side=tk.RIGHT, padx=5)

    def create_block_ui(self, parent):
        """创建分组密码界面"""
        frame = ttk.LabelFrame(parent, text="对称密码算法", padding=15, style="Section.TLabelframe")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 算法选择
        algo_frame = ttk.Frame(frame)
        algo_frame.pack(fill=tk.X, pady=10)

        ttk.Label(algo_frame, text="工作模式:", font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=5)

        self.workmode_block_algo = tk.StringVar()
        workmode_algorithms = ["ECB", "CBC", "CFB", "OFB", "CTR"]
        workmode_algo_combo = ttk.Combobox(
            algo_frame,
            textvariable=self.workmode_block_algo,
            values=workmode_algorithms,
            state="readonly",
            width=15,
            font=("Segoe UI", 10)
        )
        workmode_algo_combo.current(0)
        workmode_algo_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(algo_frame, text="选择算法:", font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=5)

        self.block_algo = tk.StringVar()
        algorithms = ["DES", "3DES", "SM4", "AES-128", "AES-192", "AES-256"]
        algo_combo = ttk.Combobox(
            algo_frame,
            textvariable=self.block_algo,
            values=algorithms,
            state="readonly",
            width=15,
            font=("Segoe UI", 10)
        )
        algo_combo.current(0)
        algo_combo.pack(side=tk.LEFT, padx=5)

        # 输入输出框架
        io_frame = ttk.Frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # 输入区
        input_frame = ttk.LabelFrame(io_frame, text="输入", padding=10, style="Section.TLabelframe")
        input_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        ttk.Label(input_frame, text="明文/密文:", font=("Segoe UI", 9)).pack(anchor=tk.W)
        self.block_input = scrolledtext.ScrolledText(
            input_frame,
            height=8,
            width=30,
            font=("Consolas", 10),
            padx=5,
            pady=5
        )
        self.block_input.pack(fill=tk.BOTH, expand=True)

        ttk.Label(input_frame, text="密钥(HEX):", font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(10, 0))
        self.block_key = ttk.Entry(
            input_frame,
            width=40,
            font=("Consolas", 10)
        )
        self.block_key.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(input_frame, text="初始向量(IV):", font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(10, 0))
        self.block_iv = ttk.Entry(
            input_frame,
            width=40,
            font=("Consolas", 10)
        )
        self.block_iv.pack(fill=tk.X, padx=5, pady=5)

        # 输出区
        output_frame = ttk.LabelFrame(io_frame, text="输出", padding=10, style="Section.TLabelframe")
        output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

        ttk.Label(output_frame, text="结果:", font=("Segoe UI", 9)).pack(anchor=tk.W)
        self.block_output = scrolledtext.ScrolledText(
            output_frame,
            height=8,
            width=30,
            font=("Consolas", 10),
            padx=5,
            pady=5
        )
        self.block_output.pack(fill=tk.BOTH, expand=True)
        self.block_output.config(state=tk.DISABLED)

        # 按钮区
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(
            btn_frame,
            text="加密",
            command=lambda: self.threaded(self.block_encrypt),
            style="Accent.TButton",
            width=10
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="解密",
            command=lambda: self.threaded(self.block_decrypt),
            width=10
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="生成随机密钥",
            command=self.generate_random_key,
            width=15
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="清空",
            command=self.clear_block,
            width=10
        ).pack(side=tk.RIGHT, padx=5)

        ttk.Button(
            btn_frame,
            text="将结果转移到输入",
            command=self.output_to_input_block,  # 指向你的交换函数
            width=15
        ).pack(side=tk.RIGHT, padx=5)

    def create_pubkey_ui(self, parent):
        """创建公钥密码界面"""
        frame = ttk.LabelFrame(parent, text="非对称密码算法", padding=15, style="Section.TLabelframe")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 算法选择
        algo_frame = ttk.Frame(frame)
        algo_frame.pack(fill=tk.X, pady=10)

        ttk.Label(algo_frame, text="选择算法:", font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=5)

        self.pubkey_algo = tk.StringVar()
        algorithms = ["RSA", "ECC"]
        algo_combo = ttk.Combobox(
            algo_frame,
            textvariable=self.pubkey_algo,
            values=algorithms,
            state="readonly",
            width=15,
            font=("Segoe UI", 10)
        )
        algo_combo.current(0)
        algo_combo.pack(side=tk.LEFT, padx=5)

        # 输入输出框架
        io_frame = ttk.Frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # 输入区
        input_frame = ttk.LabelFrame(io_frame, text="输入", padding=10, style="Section.TLabelframe")
        input_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        ttk.Label(input_frame, text="明文/密文:", font=("Segoe UI", 9)).pack(anchor=tk.W)
        self.pubkey_input = scrolledtext.ScrolledText(
            input_frame,
            height=8,
            width=30,
            font=("Consolas", 10),
            padx=5,
            pady=5
        )
        self.pubkey_input.pack(fill=tk.BOTH, expand=True)

        ttk.Label(input_frame, text="公钥:", font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(10, 0))
        self.pubkey_pub = ttk.Entry(
            input_frame,
            width=40,
            font=("Consolas", 10)
        )
        self.pubkey_pub.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(input_frame, text="私钥:", font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(10, 0))
        self.pubkey_priv = ttk.Entry(
            input_frame,
            width=40,
            font=("Consolas", 10)
        )
        self.pubkey_priv.pack(fill=tk.X, padx=5, pady=5)

        # 输出区
        output_frame = ttk.LabelFrame(io_frame, text="输出", padding=10, style="Section.TLabelframe")
        output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

        ttk.Label(output_frame, text="结果:", font=("Segoe UI", 9)).pack(anchor=tk.W)
        self.pubkey_output = scrolledtext.ScrolledText(
            output_frame,
            height=8,
            width=30,
            font=("Consolas", 10),
            padx=5,
            pady=5
        )
        self.pubkey_output.pack(fill=tk.BOTH, expand=True)
        self.pubkey_output.config(state=tk.DISABLED)

        # 按钮区
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(
            btn_frame,
            text="加密",
            command=lambda: self.threaded(self.pubkey_encrypt),
            style="Accent.TButton",
            width=10
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="解密",
            command=lambda: self.threaded(self.pubkey_decrypt),
            width=10
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="生成密钥对",
            command=self.generate_key_pair,
            width=15
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="清空",
            command=self.clear_pubkey,
            width=10
        ).pack(side=tk.RIGHT, padx=5)

        ttk.Button(
            btn_frame,
            text="输出转输入",
            command=self.output_to_input_pubkey,
            width=12
        ).pack(side=tk.RIGHT, padx=5)

    def create_hash_ui(self, parent):
        """创建哈希函数界面"""
        frame = ttk.LabelFrame(parent, text="哈希函数", padding=15, style="Section.TLabelframe")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 算法选择
        algo_frame = ttk.Frame(frame)
        algo_frame.pack(fill=tk.X, pady=10)

        ttk.Label(algo_frame, text="选择算法:", font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=5)

        self.hash_algo = tk.StringVar()
        algorithms = ["SHA-1", "SHA-256", "MD5"]
        algo_combo = ttk.Combobox(
            algo_frame,
            textvariable=self.hash_algo,
            values=algorithms,
            state="readonly",
            width=15,
            font=("Segoe UI", 10)
        )
        algo_combo.current(0)
        algo_combo.pack(side=tk.LEFT, padx=5)

        # 输入输出框架
        io_frame = ttk.Frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # 输入区
        input_frame = ttk.LabelFrame(io_frame, text="输入", padding=10, style="Section.TLabelframe")
        input_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        ttk.Label(input_frame, text="输入文本:", font=("Segoe UI", 9)).pack(anchor=tk.W)
        self.hash_input = scrolledtext.ScrolledText(
            input_frame,
            height=8,
            width=30,
            font=("Consolas", 10),
            padx=5,
            pady=5
        )
        self.hash_input.pack(fill=tk.BOTH, expand=True)

        # 输出区
        output_frame = ttk.LabelFrame(io_frame, text="输出", padding=10, style="Section.TLabelframe")
        output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

        ttk.Label(output_frame, text="哈希值:", font=("Segoe UI", 9)).pack(anchor=tk.W)
        self.hash_output = scrolledtext.ScrolledText(
            output_frame,
            height=8,
            width=30,
            font=("Consolas", 10),
            padx=5,
            pady=5
        )
        self.hash_output.pack(fill=tk.BOTH, expand=True)
        self.hash_output.config(state=tk.DISABLED)

        # 按钮区
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(
            btn_frame,
            text="计算哈希",
            command=lambda: self.threaded(self.calculate_hash),
            style="Accent.TButton",
            width=15
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="清空",
            command=self.clear_hash,
            width=10
        ).pack(side=tk.RIGHT, padx=5)

    def create_signature_ui(self, parent):
        """将数字签名的所有控件都放到 parent 上"""
        # parent 已经是一个 ttk.Frame，大小跟 notebook tab 保持一致

        # 算法区域
        control_frame = ttk.Frame(parent, padding=10)
        control_frame.pack(fill=tk.X)

        ttk.Label(control_frame, text="签名算法:").grid(row=0, column=0, sticky=tk.W)
        self.sign_algo = tk.StringVar(value="DSA")
        ttk.Combobox(control_frame,
                     textvariable=self.sign_algo,
                     values=["DSA", "ECDSA", "Ed25519", "RSA"],
                     state="readonly", width=10
                     ).grid(row=0, column=1, padx=5)

        ttk.Label(control_frame, text="密钥长度:").grid(row=0, column=2, sticky=tk.W, padx=(20, 0))
        self.key_size = tk.StringVar(value="2048")
        ttk.Combobox(control_frame,
                     textvariable=self.key_size,
                     values=["1024", "2048", "3072", "4096"],
                     state="readonly", width=8
                     ).grid(row=0, column=3, padx=5)

        ttk.Button(control_frame,
                   text="生成密钥",
                   command=lambda: self.threaded(self.generate_keys)
                   ).grid(row=0, column=4, padx=(20, 5))
        ttk.Button(control_frame,
                   text="导出公钥",
                   command=self.export_public_key
                   ).grid(row=0, column=5, padx=5)

        # 消息输入区
        msg_frame = ttk.LabelFrame(parent, text="消息")
        msg_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))
        self.message_input = scrolledtext.ScrolledText(msg_frame, height=8)
        self.message_input.pack(fill=tk.BOTH, expand=True)

        # 签名输出区
        sig_frame = ttk.LabelFrame(parent, text="签名")
        sig_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))
        self.signature_output = scrolledtext.ScrolledText(sig_frame, height=8, state=tk.DISABLED)
        self.signature_output.pack(fill=tk.BOTH, expand=True)
        self.status_label = ttk.Label(sig_frame, text="状态: 等待操作")
        self.status_label.pack(anchor=tk.W, pady=(5, 0))

        # 操作按钮
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame,
                   text="创建签名",
                   command=lambda: self.threaded(self.create_signature),
                   style="Accent.TButton"
                   ).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame,
                   text="验证签名",
                   command=lambda: self.threaded(self.verify_signature),
                   style="Accent.TButton"
                   ).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame,
                   text="清空",
                   command=self.clear_all
                   ).pack(side=tk.RIGHT, padx=5)

    def classical_encrypt(self):
        """古典密码加密操作"""
        algo = self.classical_algo.get()
        plaintext = self.classical_input.get("1.0", tk.END).strip()
        key = self.classical_key.get().strip()

        # 输入验证
        if not plaintext:
            raise ValueError("请输入明文内容")

        if not key:
            raise ValueError("请输入密钥")

        # 执行加密
        if algo == "仿射密码":
            if not re.match(r"^\d+,\s*\d+$", key):
                raise ValueError("仿射密码密钥格式应为 'a,b' (例如: 5,8)")
            a, b = map(int, key.split(','))
            try:
                result = affine_encrypt(plaintext, a, b)
            except Exception as e:
                raise ValueError(f"仿射加密过程出错：{e}")

        elif algo == "维吉尼亚密码":
            try:
                result = vigenere_encrypt(plaintext, key)
            except Exception as e:
                raise ValueError(f"维吉尼亚加密过程出错：{e}")

        elif algo == "单表代换密码":
            if len(key) != 26 or not key.isalpha():
                raise ValueError("单表代换密码密钥应为26个字母的排列")
            key_box = dict(zip('abcdefghijklmnopqrstuvwxyz', key))
            try:
                result = mono_sub_encrypt(plaintext, key_box)
            except Exception as e:
                raise ValueError(f"单表代换加密过程出错：{e}")
        elif algo == "栅栏密码":
            if not key.isdigit():
                raise ValueError("栅栏密码密钥应为整数")
            row = int(key)
            try:
                result = railfence_encrypt(plaintext, row)
            except Exception as e:
                raise ValueError(f"栅栏加密过程出错：{e}")
        elif algo == "矩阵置换密码":
            if not key.isdigit():
                raise ValueError("矩阵置换密码密钥应为数字序列 (例如: 231)")
            try:
                result = matrix_encrypt(plaintext, key)
            except Exception as e:
                raise ValueError(f"矩阵加密过程出错：{e}")
        elif algo == "凯撒密码":
            if not key.isdigit():
                raise ValueError("请输入数字")
            k = int(key)
            try:
                result = caesar_encrypt(plaintext, k)
            except Exception as e:
                raise ValueError(f"凯撒加密过程出错：{e}")
        self.clear_output()
        self.root.after(0, lambda: self.show_output(self.classical_output, result))
        self.root.after(0, lambda: self.status_var.set(f"{algo} 加密成功"))
    def classical_decrypt(self):
        """古典密码解密操作"""
        algo = self.classical_algo.get()
        ciphertext = self.classical_input.get("1.0", tk.END).strip()
        key = self.classical_key.get().strip()

        # 输入验证
        if not ciphertext:
            raise ValueError("请输入密文内容")

        if not key:
            raise ValueError("请输入密钥")

        # 执行解密
        if algo == "仿射密码":
            if not re.match(r"^\d+,\s*\d+$", key):
                raise ValueError("仿射密码密钥格式应为 'a,b' (例如: 5,8)")
            a, b = map(int, key.split(','))
            result = affine_decrypt(ciphertext, a, b)
        elif algo == "维吉尼亚密码":
            result = vigenere_decrypt(ciphertext, key)
        elif algo == "单表代换密码":
            if len(key) != 26 or not key.isalpha():
                raise ValueError("单表代换密码密钥应为26个字母的排列")
            inv_key_box = dict(zip(key, 'abcdefghijklmnopqrstuvwxyz'))
            result = mono_sub_decrypt(ciphertext, inv_key_box)
        elif algo == "栅栏密码":
            if not key.isdigit():
                raise ValueError("栅栏密码密钥应为整数")
            row = int(key)
            result = railfence_decrypt(ciphertext, row)
        elif algo == "矩阵置换密码":
            if not key.isdigit():
                raise ValueError("矩阵置换密码密钥应为数字序列 (例如: 231)")
            result = matrix_decrypt(ciphertext, key)
        elif algo == "凯撒密码":
            if not key.isdigit():
                raise ValueError("请输入数字")
            k = int(key)
            result = caesar_decrypt(ciphertext, k)
        self.clear_output()
        self.root.after(0, lambda: self.show_output(self.classical_output, result))
        self.root.after(0, lambda: self.status_var.set(f"{algo} 解密成功"))
    def clear_classical(self):
        """清空古典密码输入输出"""
        self.classical_input.delete("1.0", tk.END)
        self.classical_key.delete(0, tk.END)
        self.classical_output.config(state=tk.NORMAL)
        self.classical_output.delete("1.0", tk.END)
        self.classical_output.config(state=tk.DISABLED)
        self.status_var.set("已清空输入")
    def clear_output(self):
        self.classical_output.config(state=tk.NORMAL)
        self.classical_output.delete("1.0", tk.END)
        self.classical_output.config(state=tk.DISABLED)
    def output_to_input_classical(self):
        """将输出内容复制到输入框，并清空输出框"""
        self.classical_output.config(state=tk.NORMAL)
        output_text = self.classical_output.get("1.0", tk.END).strip()
        self.classical_output.delete("1.0", tk.END)
        self.classical_output.config(state=tk.DISABLED)

        self.classical_input.delete("1.0", tk.END)
        self.classical_input.insert(tk.END, output_text)

        self.status_var.set("已将输出转为输入")

    def block_encrypt(self):
        """分组密码加密操作"""
        algo = self.block_algo.get()
        mode = self.workmode_block_algo.get()
        plaintext = self.block_input.get("1.0", tk.END).strip()
        key_hex = self.block_key.get().strip()
        iv_hex = self.block_iv.get().strip()
        # 输入验证
        if not plaintext:
            raise ValueError("请输入明文内容")

        if not key_hex:
            raise ValueError("请输入密钥")

        if mode in ["CBC", "CFB", "OFB", "CTR"] and not iv_hex:
            raise ValueError("请输入初始向量(IV))")

        if not re.match(r"^[0-9a-fA-F]+$", key_hex):
            raise ValueError("密钥应为十六进制字符串")

        if mode in ["CBC", "CFB", "OFB", "CTR"] and not re.match(r"^[0-9a-fA-F]+$", iv_hex):
            raise ValueError("初始向量(IV)应为十六进制字符串")

        if algo == '3DES' and len(key_hex) != 48:
            raise ValueError("密钥应为24字节")

        if algo == 'DES' and len(key_hex) != 16:
            raise ValueError("密钥应为8字节")


        if algo in ['AES-128', 'SM4'] and len(key_hex) != 32:
            raise ValueError("密钥应为16字节")

        if algo == 'AES-192' and len(key_hex) != 48:
            raise ValueError("密钥应为24字节")

        if algo == 'AES-256' and len(key_hex) != 64:
            raise ValueError("密钥应为32字节")

        if mode in ["CBC", "CFB", "OFB", "CTR"] and algo == '3DES' and len(iv_hex) != 16:
            raise ValueError("初始向量(IV)应为8字节")

        if mode in ["CBC", "CFB", "OFB", "CTR"] and algo in ["AES-128", "AES-192", "AES-256", "SM4"] and len(iv_hex) != 32:
            raise ValueError("初始向量(IV)应为16字节")

        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex) if iv_hex else None
        plaintext = plaintext.encode('utf-8')

        # 执行加密
        if algo == "DES":
            result = des_encrypt_decrypt(plaintext, key, iv, mode, encrypt=True)
        elif algo == "3DES":
            result = tripledes_encrypt_decrypt(plaintext, key, iv, mode, encrypt=True)
        elif algo.startswith("AES"):
            result = aes_encrypt_decrypt(plaintext, key, iv, mode, encrypt=True)
        elif algo == "SM4":
            result = sm4_encrypt_decrypt(plaintext, iv_hex, key_hex, mode, encrypt=True)

        self.root.after(0, lambda: self.show_output(self.block_output, result.hex()))
        self.root.after(0, lambda: self.status_var.set(f"{algo} 加密成功"))
    def block_decrypt(self):
        """分组密码解密操作"""
        algo = self.block_algo.get()
        mode = self.workmode_block_algo.get()
        plaintext = self.block_input.get("1.0", tk.END).strip()
        key_hex = self.block_key.get().strip()
        iv_hex = self.block_iv.get().strip()
        # 输入验证
        if not plaintext:
            raise ValueError("请输入密文内容")

        if not key_hex:
            raise ValueError("请输入密钥")

        if mode in ["CBC", "CFB", "OFB", "CTR"] and not iv_hex:
            raise ValueError("请输入初始向量(IV))")

        if not re.match(r"^[0-9a-fA-F]+$", key_hex):
            raise ValueError("密钥应为十六进制字符串")

        if mode in ["CBC", "CFB", "OFB", "CTR"] and not re.match(r"^[0-9a-fA-F]+$", iv_hex):
            raise ValueError("初始向量(IV)应为十六进制字符串")

        if algo == '3DES' and len(key_hex) != 48:
            raise ValueError("密钥应为24字节")

        if algo == 'DES' and len(key_hex) != 16:
            raise ValueError("密钥应为8字节")


        if algo in ['AES-128', 'SM4'] and len(key_hex) != 32:
            raise ValueError("密钥应为16字节")

        if algo == 'AES-192' and len(key_hex) != 48:
            raise ValueError("密钥应为24字节")

        if algo == 'AES-256' and len(key_hex) != 64:
            raise ValueError("密钥应为32字节")

        if mode in ["CBC", "CFB", "OFB", "CTR"] and algo == '3DES' and len(iv_hex) != 16:
            raise ValueError("初始向量(IV)应为8字节")

        if mode in ["CBC", "CFB", "OFB", "CTR"] and algo in ["AES-128", "AES-192", "AES-256", "SM4"] and len(iv_hex) != 32:
            raise ValueError("初始向量(IV)应为16字节")

        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex) if iv_hex else None
        plaintext = bytes.fromhex(plaintext)

        # 执行解密
        if algo == "DES":
            result = des_encrypt_decrypt(plaintext, key, iv, mode, encrypt=False)
        elif algo == "3DES":
            result = tripledes_encrypt_decrypt(plaintext, key, iv, mode, encrypt=False)
        elif algo.startswith("AES"):
            result = aes_encrypt_decrypt(plaintext, key, iv, mode, encrypt=False)
        elif algo == "SM4":
            result = sm4_encrypt_decrypt(plaintext, iv_hex, key_hex, mode, encrypt=False)

        self.root.after(0, lambda: self.show_output(self.block_output, result.decode()))
        self.root.after(0, lambda: self.status_var.set(f"{algo} 解密成功"))
    def generate_random_key(self):
        """生成随机密钥"""
        algo = self.block_algo.get()
        mode = self.workmode_block_algo.get()
        self.block_iv.delete(0, tk.END)
        self.block_key.delete(0, tk.END)
        if algo == "DES":
            random_key = os.urandom(8)
        elif algo == "3DES":
            random_key = os.urandom(24)
        elif algo == "SM4":
            random_key = os.urandom(16)
        elif algo == "AES-128":
            random_key = os.urandom(16)
        elif algo == "AES-192":
            random_key = os.urandom(24)
        elif algo == "AES-256":
            random_key = os.urandom(32)
        if mode != "ECB":
            if algo in ["3DES", "DES"]:
                iv = os.urandom(8)
            else:
                iv = os.urandom(16)
            self.block_iv.insert(0, iv.hex())
        self.block_key.insert(0, random_key.hex())
        self.status_var.set("已生成随机密钥")
    def clear_block(self):
        """清空分组密码输入输出"""
        self.block_input.delete("1.0", tk.END)
        self.block_key.delete(0, tk.END)
        self.block_iv.delete(0, tk.END)
        self.block_output.config(state=tk.NORMAL)
        self.block_output.delete("1.0", tk.END)
        self.block_output.config(state=tk.DISABLED)
        self.status_var.set("已清空分组密码输入")
    def output_to_input_block(self):
        """将输出内容复制到输入框，并清空输出框"""
        self.block_output.config(state=tk.NORMAL)
        output_text = self.block_output.get("1.0", tk.END).strip()
        self.block_output.delete("1.0", tk.END)
        self.block_output.config(state=tk.DISABLED)

        self.block_input.delete("1.0", tk.END)
        self.block_input.insert(tk.END, output_text)

        self.status_var.set("已将输出转为输入")

    def pubkey_encrypt(self):
        """公钥密码加密操作"""
        plaintext = self.pubkey_input.get("1.0", tk.END).strip()
        pub_key = self.pubkey_pub.get().strip()
        algo = self.pubkey_algo.get()
        # 输入验证
        if not plaintext:
            raise ValueError("请输入明文内容")

        if not pub_key:
            raise ValueError("请输入公钥")

        # 验证公钥格式
        if algo == "RSA" and not re.match(r"^\d+,\s*\d+$", pub_key):
            raise ValueError("公钥格式应为 'e,n' (例如: 65537,123456789)")

        # 执行加密
        if algo == "RSA":
            e, n = map(int, pub_key.split(','))
            result = rsa_encrypt_str(plaintext, (e, n))
        elif algo == "ECC":
            # 拆分输入字符串
            plaintext = plaintext.encode('utf-8')
            parts = pub_key.split(',')
            if len(parts) != 3:
                raise ValueError("输入公钥格式错误，请输入发送方私钥接收方公钥，应为: priv,x,y")

            # 尝试将每个部分转换为整数（支持十六进制或十进制）
            priv_str, pub_x_str, pub_y_str = parts
            priv = int(priv_str, 16 if '0x' in priv_str else 10)
            pub_x = int(pub_x_str, 16 if '0x' in pub_x_str else 10)
            pub_y = int(pub_y_str, 16 if '0x' in pub_y_str else 10)

            # 尝试还原私钥
            private_key = ec.derive_private_key(priv, ec.SECP256R1())

            # 尝试还原公钥
            pub_numbers = ec.EllipticCurvePublicNumbers(pub_x, pub_y, ec.SECP256R1())
            public_key = pub_numbers.public_key()

            result = ecc_encrypt(plaintext, private_key, public_key).hex()

        self.root.after(0, lambda: self.show_output(self.pubkey_output, result))
        self.root.after(0, lambda: self.status_var.set(f"{algo} 加密成功"))
    def pubkey_decrypt(self):
        """公钥密码解密操作"""
        ciphertext = self.pubkey_input.get("1.0", tk.END).strip()
        priv_key = self.pubkey_priv.get().strip()
        algo = self.pubkey_algo.get()

        # 输入验证
        if not ciphertext:
            raise ValueError("请输入密文内容")

        if not priv_key:
            raise ValueError("请输入私钥")

        # 验证私钥格式
        if algo == "RSA" and not re.match(r"^\d+,\s*\d+$", priv_key):
            raise ValueError("私钥格式应为 'd,n' (例如: 123456789,987654321)")

        if algo == "RSA" and not re.fullmatch(r"[0-9a-fA-F]+", ciphertext):
            raise ValueError("RSA 密文应为十六进制字符串")


        # 执行解密
        if algo == "RSA":
            d, n = map(int, priv_key.split(','))
            result = rsa_decrypt_str(ciphertext, (d, n))
        elif algo == "ECC":
            # 解密前准备：hex -> bytes
            ciphertext = bytes.fromhex(ciphertext)

            if not priv_key:
                raise ValueError("请输入私钥或私钥+公钥")

            parts = priv_key.strip().split(',')

            # 解析私钥
            priv_str = parts[0]
            priv = int(priv_str, 16 if '0x' in priv_str else 10)
            private_key = ec.derive_private_key(priv, ec.SECP256R1())

            if len(parts) != 3:
                raise ValueError("输入私钥格式错误，请输入接收方私钥接发送方公钥，应为：priv,x,y")
            # 提供了公钥坐标，则解析并检查匹配
            pub_x_str, pub_y_str = parts[1], parts[2]
            pub_x = int(pub_x_str, 16 if '0x' in pub_x_str else 10)
            pub_y = int(pub_y_str, 16 if '0x' in pub_y_str else 10)

            # 构造公钥对象
            pub_numbers = ec.EllipticCurvePublicNumbers(pub_x, pub_y, ec.SECP256R1())
            public_key = pub_numbers.public_key()
            # 执行 ECC 解密
            result = ecc_decrypt(ciphertext, private_key, public_key).decode('utf-8')

        self.root.after(0, lambda: self.show_output(self.pubkey_output, result))
        self.root.after(0, lambda: self.status_var.set(f"{algo} 解密成功"))
    def generate_key_pair(self):
        """生成RSA密钥对"""
        algo = self.pubkey_algo.get()
        if algo == "RSA":
            try:
                key_size = 1024  # 密钥长度
                pk, sk = rsa_key_gen(key_size)

                self.pubkey_pub.delete(0, tk.END)
                self.pubkey_pub.insert(0, f"{pk[0]},{pk[1]}")

                self.pubkey_priv.delete(0, tk.END)
                self.pubkey_priv.insert(0, f"{sk[0]},{sk[1]}")

                self.status_var.set("已生成RSA密钥对")
            except Exception as e:
                messagebox.showerror("密钥生成错误", f"密钥生成失败: {str(e)}")
                self.status_var.set(f"密钥生成失败: {str(e)}")
        elif algo == "ECC":
            try:
                sender_priv, sender_pub = generate_key_pair()
                receiver_priv, receiver_pub = generate_key_pair()

                sender_priv_number = sender_priv.private_numbers().private_value
                sender_pub_x = sender_pub.public_numbers().x
                sender_pub_y = sender_pub.public_numbers().y
                receiver_priv_number = receiver_priv.private_numbers().private_value
                receiver_pub_x = receiver_pub.public_numbers().x
                receiver_pub_y = receiver_pub.public_numbers().y

                self.pubkey_pub.delete(0, tk.END)
                self.pubkey_pub.insert(0, f"{sender_priv_number},{receiver_pub_x},{receiver_pub_y}")

                self.pubkey_priv.delete(0, tk.END)
                self.pubkey_priv.insert(0, f"{receiver_priv_number}, {sender_pub_x}, {sender_pub_y}")
                self.status_var.set("已生成ECC密钥对")
            except Exception as e:
                messagebox.showerror("密钥生成错误", f"密钥生成失败: {str(e)}")
                self.status_var.set(f"密钥生成失败: {str(e)}")


    def clear_pubkey(self):
        """清空公钥密码输入输出"""
        self.pubkey_input.delete("1.0", tk.END)
        self.pubkey_pub.delete(0, tk.END)
        self.pubkey_priv.delete(0, tk.END)
        self.pubkey_output.config(state=tk.NORMAL)
        self.pubkey_output.delete("1.0", tk.END)
        self.pubkey_output.config(state=tk.DISABLED)
        self.status_var.set("已清空公钥密码输入")
    def output_to_input_pubkey(self):
        """将输出内容复制到输入框，并清空输出框"""
        self.pubkey_output.config(state=tk.NORMAL)
        output_text = self.pubkey_output.get("1.0", tk.END).strip()
        self.pubkey_output.delete("1.0", tk.END)
        self.pubkey_output.config(state=tk.DISABLED)

        self.pubkey_input.delete("1.0", tk.END)
        self.pubkey_input.insert(tk.END, output_text)

        self.status_var.set("已将输出转为输入")

    def calculate_hash(self):
        """计算哈希值"""
        text = self.hash_input.get("1.0", tk.END).strip()

        # 输入验证
        if not text:
            raise ValueError("请输入要计算哈希的内容")

        # 执行计算
        algo = self.hash_algo.get()
        if algo == "SHA-1":
            result = sha1_hexdigest(text.encode('utf-8'))
        elif algo == "SHA-256":
            import hashlib
            result = hashlib.md5(text.encode()).hexdigest()
        elif algo == "MD5":
            import hashlib
            result = hashlib.sha256(text.encode()).hexdigest()

        self.root.after(0, lambda: self.show_output(self.hash_output, result))
        self.root.after(0, lambda: self.status_var.set(f"{algo} 哈希计算成功"))
    def clear_hash(self):
        """清空哈希函数输入输出"""
        self.hash_input.delete("1.0", tk.END)
        self.hash_output.config(state=tk.NORMAL)
        self.hash_output.delete("1.0", tk.END)
        self.hash_output.config(state=tk.DISABLED)
        self.status_var.set("已清空哈希输入")

    def generate_keys(self):
        """生成密钥对"""
        algorithm = self.sign_algo.get()
        key_size = int(self.key_size.get())

        try:
            if algorithm == "DSA":
                self.private_key = dsa.generate_private_key(key_size=key_size)
            elif algorithm == "ECDSA":
                self.private_key = ec.generate_private_key(ec.SECP256R1())
            elif algorithm == "Ed25519":
                self.private_key = ed25519.Ed25519PrivateKey.generate()
            elif algorithm == "RSA":
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size
                )

            self.public_key = self.private_key.public_key()
            self.update_status(f"已生成 {algorithm} 密钥对 ({key_size}位)")
        except Exception as e:
            self.update_status(f"密钥生成失败: {str(e)}")

    def create_signature(self):
        """创建数字签名"""
        if not self.private_key:
            self.update_status("错误: 请先生成密钥对")
            return

        message = self.message_input.get("1.0", tk.END).strip().encode('utf-8')
        if not message:
            self.update_status("错误: 请输入要签名的消息")
            return

        try:
            algorithm = self.sign_algo.get()

            if algorithm == "DSA":
                # DSA和ECDSA需要单独的哈希步骤
                signature = self.private_key.sign(
                    message,
                    hashes.SHA256()
                )

                # 将DSA/ECDSA签名转换为可读格式 (r, s)
                r, s = decode_dss_signature(signature)
                sig_str = f"r = {r}\ns = {s}\n\nHex: {signature.hex()}"
            elif algorithm == "ECDSA":
                signature = self.private_key.sign(
                    message,
                    ec.ECDSA(hashes.SHA256())
                )

                # 将DSA/ECDSA签名转换为可读格式 (r, s)
                r, s = decode_dss_signature(signature)
                sig_str = f"r = {r}\ns = {s}\n\nHex: {signature.hex()}"

            elif algorithm == "Ed25519":
                signature = self.private_key.sign(message)
                sig_str = f"Hex: {signature.hex()}"
            elif algorithm == "RSA":
                signature = self.private_key.sign(
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                sig_str = f"Hex: {signature.hex()}"

            self.signature = signature
            self.show_signature(sig_str)
            self.update_status(f"已创建 {algorithm} 签名")
        except Exception as e:
            self.update_status(f"签名失败: {str(e)}")

    def verify_signature(self):
        """验证数字签名"""
        if not self.public_key or not self.signature:
            self.update_status("错误: 缺少密钥或签名")
            return

        message = self.message_input.get("1.0", tk.END).strip().encode('utf-8')
        if not message:
            self.update_status("错误: 请输入要验证的消息")
            return

        try:
            algorithm = self.sign_algo.get()

            if algorithm == "DSA":
                self.public_key.verify(
                    self.signature,
                    message,
                    hashes.SHA256()
                )
            elif algorithm == "ECDSA":
                self.signature,
                message,
                ec.ECDSA(hashes.SHA256())
            elif algorithm == "Ed25519":
                self.public_key.verify(self.signature, message)
            elif algorithm == "RSA":
                self.public_key.verify(
                    self.signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

            self.update_status(f"{algorithm} 签名验证成功!", "green")
        except InvalidSignature:
            self.update_status("签名验证失败: 无效签名", "red")
        except Exception as e:
            self.update_status(f"验证失败: {str(e)}", "red")

    def export_public_key(self):
        """导出公钥"""
        if not self.public_key:
            self.update_status("错误: 请先生成密钥对")
            return

        try:
            pub_key_pem = self.public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            self.signature_output.config(state=tk.NORMAL)
            self.signature_output.delete(1.0, tk.END)
            self.signature_output.insert(tk.END, "----- 公钥 -----\n")
            self.signature_output.insert(tk.END, pub_key_pem)
            self.signature_output.config(state=tk.DISABLED)
            self.update_status("已导出公钥 (PEM格式)")
        except Exception as e:
            self.update_status(f"导出公钥失败: {str(e)}")

    def show_signature(self, signature_str):
        """在输出区域显示签名"""
        self.signature_output.config(state=tk.NORMAL)
        self.signature_output.delete(1.0, tk.END)
        self.signature_output.insert(tk.END, signature_str)
        self.signature_output.config(state=tk.DISABLED)

    def update_status(self, message, color="black"):
        """更新状态标签"""
        self.status_label.config(text=f"状态: {message}", foreground=color)

    def clear_all(self):
        """清空所有内容"""
        self.message_input.delete(1.0, tk.END)

        self.signature_output.config(state=tk.NORMAL)
        self.signature_output.delete(1.0, tk.END)
        self.signature_output.config(state=tk.DISABLED)

        self.private_key = None
        self.public_key = None
        self.signature = None

        self.update_status("已重置所有内容")


    def show_output(self, widget, text):
        """在输出控件中显示文本，并且将其设为只读"""
        widget.config(state=tk.NORMAL)  # 切换到可写
        widget.delete("1.0", tk.END)  # 清空旧内容
        widget.insert(tk.END, text)  # 写入新内容
        widget.config(state=tk.DISABLED)  # 切回只读


if __name__=='__main__':
    root=tk.Tk()
    app=CryptoApp(root)
    root.mainloop()
