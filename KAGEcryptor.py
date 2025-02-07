#!/usr/bin/env python3
"""
==========================================================================
                          KAGEcryptor - Interface Graphique
==========================================================================
Chiffrement et déchiffrement de Texte, Fichiers et Images
avec plusieurs algorithmes (Caesar, Vigenère, XOR et AES),
le support du glisser-déposer, multi-threading, thèmes personnalisables
et sauvegarde des préférences.

Auteur      : GUY KOUAKOU
Alias       : KAGEH@CK3R
Version     : 3.0
==========================================================================
"""

import sys
import logging
import base64
import hashlib
import traceback

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QTextEdit, QLabel, QPushButton, QLineEdit, QFileDialog, QMessageBox,
    QCheckBox, QComboBox, QProgressBar, QAction
)
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt, QThreadPool, QRunnable, pyqtSlot, QObject, pyqtSignal, QSettings

# Pour AES, on utilise pycryptodome
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    AES = None

# Configuration de la journalisation
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


# ============================================================================
# Fonctions d'encryption/décryption pour le texte
# ============================================================================

def caesar_encrypt_text(text: str, shift: int) -> str:
    """Chiffrement de César appliqué sur tous les caractères (univers Unicode)."""
    return ''.join(chr((ord(c) + shift) % 0x110000) for c in text)

def caesar_decrypt_text(text: str, shift: int) -> str:
    return caesar_encrypt_text(text, -shift)

def vigenere_encrypt_text(text: str, key: str) -> str:
    if not key:
        return text
    result = []
    key_len = len(key)
    for i, c in enumerate(text):
        result.append(chr((ord(c) + ord(key[i % key_len])) % 0x110000))
    return ''.join(result)

def vigenere_decrypt_text(text: str, key: str) -> str:
    if not key:
        return text
    result = []
    key_len = len(key)
    for i, c in enumerate(text):
        result.append(chr((ord(c) - ord(key[i % key_len])) % 0x110000))
    return ''.join(result)

def xor_encrypt_text(text: str, key: str) -> str:
    if not key:
        return text
    key_bytes = key.encode('utf-8')
    text_bytes = text.encode('utf-8')
    result_bytes = bytearray()
    for i, b in enumerate(text_bytes):
        result_bytes.append(b ^ key_bytes[i % len(key_bytes)])
    # Encodage en base64 pour afficher un résultat lisible
    return base64.b64encode(result_bytes).decode('utf-8')

def xor_decrypt_text(text: str, key: str) -> str:
    if not key:
        return text
    key_bytes = key.encode('utf-8')
    try:
        enc_bytes = base64.b64decode(text)
    except Exception:
        return "Erreur : encodage base64 invalide."
    result_bytes = bytearray()
    for i, b in enumerate(enc_bytes):
        result_bytes.append(b ^ key_bytes[i % len(key_bytes)])
    try:
        return result_bytes.decode('utf-8')
    except Exception:
        return "Erreur : problème de décodage."

def aes_encrypt_text(text: str, key: str) -> str:
    if AES is None:
        return "Erreur : PyCryptodome non installé."
    # Utilise SHA256 pour dériver une clé 32 octets
    key_hash = hashlib.sha256(key.encode('utf-8')).digest()
    cipher = AES.new(key_hash, AES.MODE_ECB)
    text_bytes = text.encode('utf-8')
    padded = pad(text_bytes, AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode('utf-8')

def aes_decrypt_text(text: str, key: str) -> str:
    if AES is None:
        return "Erreur : PyCryptodome non installé."
    key_hash = hashlib.sha256(key.encode('utf-8')).digest()
    cipher = AES.new(key_hash, AES.MODE_ECB)
    try:
        enc_bytes = base64.b64decode(text)
        decrypted = cipher.decrypt(enc_bytes)
        unpadded = unpad(decrypted, AES.block_size)
        return unpadded.decode('utf-8')
    except Exception as e:
        return f"Erreur de déchiffrement AES : {e}"


# ============================================================================
# Fonctions d'encryption/décryption pour les fichiers (données en octets)
# ============================================================================

def caesar_encrypt_bytes(data: bytes, shift: int) -> bytes:
    return bytes((b + shift) % 256 for b in data)

def caesar_decrypt_bytes(data: bytes, shift: int) -> bytes:
    return caesar_encrypt_bytes(data, -shift)

def vigenere_encrypt_bytes(data: bytes, key: str) -> bytes:
    if not key:
        return data
    key_bytes = key.encode('utf-8')
    result = bytearray()
    for i, b in enumerate(data):
        result.append((b + key_bytes[i % len(key_bytes)]) % 256)
    return bytes(result)

def vigenere_decrypt_bytes(data: bytes, key: str) -> bytes:
    if not key:
        return data
    key_bytes = key.encode('utf-8')
    result = bytearray()
    for i, b in enumerate(data):
        result.append((b - key_bytes[i % len(key_bytes)]) % 256)
    return bytes(result)

def xor_encrypt_bytes(data: bytes, key: str) -> bytes:
    if not key:
        return data
    key_bytes = key.encode('utf-8')
    result = bytearray()
    for i, b in enumerate(data):
        result.append(b ^ key_bytes[i % len(key_bytes)])
    return bytes(result)

def xor_decrypt_bytes(data: bytes, key: str) -> bytes:
    return xor_encrypt_bytes(data, key)

def aes_encrypt_bytes(data: bytes, key: str) -> bytes:
    if AES is None:
        return None
    key_hash = hashlib.sha256(key.encode('utf-8')).digest()
    cipher = AES.new(key_hash, AES.MODE_ECB)
    padded = pad(data, AES.block_size)
    encrypted = cipher.encrypt(padded)
    return encrypted

def aes_decrypt_bytes(data: bytes, key: str) -> bytes:
    if AES is None:
        return None
    key_hash = hashlib.sha256(key.encode('utf-8')).digest()
    cipher = AES.new(key_hash, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(data)
        unpadded = unpad(decrypted, AES.block_size)
        return unpadded
    except Exception:
        return None


# ============================================================================
# Worker pour le chiffrement/déchiffrement de fichiers (multi-threading)
# ============================================================================

class FileWorkerSignals(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(str)
    progress = pyqtSignal(int)

class FileWorker(QRunnable):
    def __init__(self, file_path: str, output_path: str, key: str, algorithm: str, operation: str):
        super().__init__()
        self.file_path = file_path
        self.output_path = output_path
        self.key = key
        self.algorithm = algorithm
        self.operation = operation  # "encrypt" ou "decrypt"
        self.signals = FileWorkerSignals()

    @pyqtSlot()
    def run(self):
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
            self.signals.progress.emit(50)
            if self.operation == "encrypt":
                if self.algorithm == "Caesar":
                    try:
                        shift = int(self.key)
                    except ValueError:
                        self.signals.error.emit("La clé doit être un entier pour Caesar.")
                        return
                    result = caesar_encrypt_bytes(data, shift)
                elif self.algorithm == "Vigenère":
                    result = vigenere_encrypt_bytes(data, self.key)
                elif self.algorithm == "XOR":
                    result = xor_encrypt_bytes(data, self.key)
                elif self.algorithm == "AES":
                    result = aes_encrypt_bytes(data, self.key)
                    if result is None:
                        self.signals.error.emit("Erreur AES : PyCryptodome non installé.")
                        return
                else:
                    self.signals.error.emit("Algorithme inconnu.")
                    return
            else:  # operation "decrypt"
                if self.algorithm == "Caesar":
                    try:
                        shift = int(self.key)
                    except ValueError:
                        self.signals.error.emit("La clé doit être un entier pour Caesar.")
                        return
                    result = caesar_decrypt_bytes(data, shift)
                elif self.algorithm == "Vigenère":
                    result = vigenere_decrypt_bytes(data, self.key)
                elif self.algorithm == "XOR":
                    result = xor_decrypt_bytes(data, self.key)
                elif self.algorithm == "AES":
                    result = aes_decrypt_bytes(data, self.key)
                    if result is None:
                        self.signals.error.emit("Erreur lors du décryptage AES.")
                        return
                else:
                    self.signals.error.emit("Algorithme inconnu.")
                    return
            self.signals.progress.emit(100)
            with open(self.output_path, "wb") as f:
                f.write(result)
            self.signals.finished.emit()
        except Exception:
            err_msg = traceback.format_exc()
            self.signals.error.emit(err_msg)


# ============================================================================
# Onglet Texte
# ============================================================================

class TextTab(QWidget):
    def __init__(self, settings: QSettings):
        super().__init__()
        self.settings = settings
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Zone de saisie
        self.input_label = QLabel("Texte à chiffrer/déchiffrer :")
        self.input_text = QTextEdit()
        
        # Saisie de la clé et sélection d'algorithme
        key_layout = QHBoxLayout()
        self.key_label = QLabel("Clé :")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Entrez la clé...")
        self.alg_combo = QComboBox()
        self.alg_combo.addItems(["Caesar", "Vigenère", "XOR", "AES"])
        self.alg_combo.currentTextChanged.connect(self.update_key_placeholder)
        key_layout.addWidget(self.key_label)
        key_layout.addWidget(self.key_input)
        key_layout.addWidget(QLabel("Algorithme :"))
        key_layout.addWidget(self.alg_combo)
        
        # Option d'auto-copie
        self.auto_copy_checkbox = QCheckBox("Copier automatiquement le résultat")
        
        # Boutons d'action
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Chiffrer")
        self.decrypt_button = QPushButton("Déchiffrer")
        self.copy_button = QPushButton("Copier")
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        button_layout.addWidget(self.copy_button)
        
        # Zone de résultat
        self.output_label = QLabel("Résultat :")
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        
        layout.addWidget(self.input_label)
        layout.addWidget(self.input_text)
        layout.addLayout(key_layout)
        layout.addWidget(self.auto_copy_checkbox)
        layout.addLayout(button_layout)
        layout.addWidget(self.output_label)
        layout.addWidget(self.output_text)
        
        self.setLayout(layout)
        
        # Connexions
        self.encrypt_button.clicked.connect(self.encrypt_text)
        self.decrypt_button.clicked.connect(self.decrypt_text)
        self.copy_button.clicked.connect(self.copy_result)
        
        self.load_preferences()
    
    def update_key_placeholder(self, alg: str):
        if alg == "Caesar":
            self.key_input.setPlaceholderText("Entrez un entier (ex: 3)")
        elif alg == "Vigenère":
            self.key_input.setPlaceholderText("Entrez une clé textuelle (ex: secret)")
        elif alg == "XOR":
            self.key_input.setPlaceholderText("Entrez une clé textuelle (ex: key)")
        elif alg == "AES":
            self.key_input.setPlaceholderText("Entrez une clé (sera hashée avec SHA256)")
    
    def encrypt_text(self):
        alg = self.alg_combo.currentText()
        key = self.key_input.text()
        text = self.input_text.toPlainText()
        try:
            if alg == "Caesar":
                shift = int(key)
                result = caesar_encrypt_text(text, shift)
            elif alg == "Vigenère":
                result = vigenere_encrypt_text(text, key)
            elif alg == "XOR":
                result = xor_encrypt_text(text, key)
            elif alg == "AES":
                result = aes_encrypt_text(text, key)
            else:
                result = "Algorithme inconnu."
        except Exception as e:
            result = f"Erreur: {e}"
        self.output_text.setPlainText(result)
        if self.auto_copy_checkbox.isChecked():
            self.copy_to_clipboard(result)
    
    def decrypt_text(self):
        alg = self.alg_combo.currentText()
        key = self.key_input.text()
        text = self.input_text.toPlainText()
        try:
            if alg == "Caesar":
                shift = int(key)
                result = caesar_decrypt_text(text, shift)
            elif alg == "Vigenère":
                result = vigenere_decrypt_text(text, key)
            elif alg == "XOR":
                result = xor_decrypt_text(text, key)
            elif alg == "AES":
                result = aes_decrypt_text(text, key)
            else:
                result = "Algorithme inconnu."
        except Exception as e:
            result = f"Erreur: {e}"
        self.output_text.setPlainText(result)
        if self.auto_copy_checkbox.isChecked():
            self.copy_to_clipboard(result)
    
    def copy_result(self):
        result = self.output_text.toPlainText()
        if result:
            self.copy_to_clipboard(result)
            QMessageBox.information(self, "Copié", "Le résultat a été copié dans le presse-papier.")
        else:
            QMessageBox.warning(self, "Erreur", "Rien à copier.")
    
    def copy_to_clipboard(self, text: str):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
    
    def load_preferences(self):
        alg = self.settings.value("text_alg", "Caesar")
        self.alg_combo.setCurrentText(alg)
        key = self.settings.value("text_key", "")
        self.key_input.setText(key)
        auto_copy = self.settings.value("auto_copy", "false") == "true"
        self.auto_copy_checkbox.setChecked(auto_copy)
    
    def save_preferences(self):
        self.settings.setValue("text_alg", self.alg_combo.currentText())
        self.settings.setValue("text_key", self.key_input.text())
        self.settings.setValue("auto_copy", "true" if self.auto_copy_checkbox.isChecked() else "false")


# ============================================================================
# Onglet Fichiers/Images (avec glisser-déposer et multi-threading)
# ============================================================================

class FileTab(QWidget):
    def __init__(self, settings: QSettings, threadpool: QThreadPool):
        super().__init__()
        self.settings = settings
        self.threadpool = threadpool
        self.file_path = ""
        self.init_ui()
        self.setAcceptDrops(True)
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Sélection du fichier
        file_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Sélectionnez un fichier ou déposez-le ici...")
        self.browse_button = QPushButton("Parcourir")
        file_layout.addWidget(self.file_path_input)
        file_layout.addWidget(self.browse_button)
        
        # Saisie de la clé et choix de l'algorithme
        key_layout = QHBoxLayout()
        self.key_label = QLabel("Clé :")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Entrez la clé...")
        self.alg_combo = QComboBox()
        self.alg_combo.addItems(["Caesar", "Vigenère", "XOR", "AES"])
        self.alg_combo.currentTextChanged.connect(self.update_key_placeholder)
        key_layout.addWidget(self.key_label)
        key_layout.addWidget(self.key_input)
        key_layout.addWidget(QLabel("Algorithme :"))
        key_layout.addWidget(self.alg_combo)
        
        # Boutons d'action
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Chiffrer le fichier")
        self.decrypt_button = QPushButton("Déchiffrer le fichier")
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        
        # Barre de progression
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        
        # Aperçu (pour les images)
        self.preview_label = QLabel("Aperçu de l'image (si applicable)")
        self.preview_label.setAlignment(Qt.AlignCenter)
        self.preview_label.setFixedSize(300, 300)
        self.preview_label.setStyleSheet("border: 1px solid gray;")
        
        layout.addLayout(file_layout)
        layout.addLayout(key_layout)
        layout.addLayout(button_layout)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.preview_label)
        self.setLayout(layout)
        
        # Connexions
        self.browse_button.clicked.connect(self.browse_file)
        self.encrypt_button.clicked.connect(self.encrypt_file)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        
        self.load_preferences()
    
    def update_key_placeholder(self, alg: str):
        if alg == "Caesar":
            self.key_input.setPlaceholderText("Entrez un entier (ex: 3)")
        elif alg == "Vigenère":
            self.key_input.setPlaceholderText("Entrez une clé textuelle (ex: secret)")
        elif alg == "XOR":
            self.key_input.setPlaceholderText("Entrez une clé textuelle (ex: key)")
        elif alg == "AES":
            self.key_input.setPlaceholderText("Entrez une clé (sera hashée avec SHA256)")
    
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Sélectionner un fichier", "", "Tous les fichiers (*)")
        if file_path:
            self.file_path = file_path
            self.file_path_input.setText(file_path)
            self.update_preview(file_path)
    
    def update_preview(self, file_path: str):
        if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
            pixmap = QPixmap(file_path)
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaled(self.preview_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.preview_label.setPixmap(scaled_pixmap)
            else:
                self.preview_label.setText("Aucun aperçu disponible")
        else:
            self.preview_label.setPixmap(QPixmap())
            self.preview_label.setText("Aucun aperçu disponible")
    
    # Gestion du glisser-déposer
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.file_path = file_path
            self.file_path_input.setText(file_path)
            self.update_preview(file_path)
    
    def encrypt_file(self):
        if not self.file_path:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner un fichier.")
            return
        key = self.key_input.text()
        alg = self.alg_combo.currentText()
        output_path, _ = QFileDialog.getSaveFileName(self, "Enregistrer le fichier chiffré", self.file_path + ".enc", "Tous les fichiers (*)")
        if not output_path:
            return
        worker = FileWorker(self.file_path, output_path, key, alg, "encrypt")
        worker.signals.progress.connect(self.progress_bar.setValue)
        worker.signals.error.connect(lambda err: QMessageBox.critical(self, "Erreur", err))
        worker.signals.finished.connect(lambda: QMessageBox.information(self, "Succès", f"Fichier chiffré sauvegardé :\n{output_path}"))
        self.threadpool.start(worker)
    
    def decrypt_file(self):
        if not self.file_path:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner un fichier.")
            return
        key = self.key_input.text()
        alg = self.alg_combo.currentText()
        output_path, _ = QFileDialog.getSaveFileName(self, "Enregistrer le fichier déchiffré", self.file_path + ".dec", "Tous les fichiers (*)")
        if not output_path:
            return
        worker = FileWorker(self.file_path, output_path, key, alg, "decrypt")
        worker.signals.progress.connect(self.progress_bar.setValue)
        worker.signals.error.connect(lambda err: QMessageBox.critical(self, "Erreur", err))
        worker.signals.finished.connect(lambda: QMessageBox.information(self, "Succès", f"Fichier déchiffré sauvegardé :\n{output_path}"))
        self.threadpool.start(worker)
    
    def load_preferences(self):
        alg = self.settings.value("file_alg", "Caesar")
        self.alg_combo.setCurrentText(alg)
        key = self.settings.value("file_key", "")
        self.key_input.setText(key)
    
    def save_preferences(self):
        self.settings.setValue("file_alg", self.alg_combo.currentText())
        self.settings.setValue("file_key", self.key_input.text())


# ============================================================================
# Fenêtre Principale avec gestion du thème et sauvegarde des préférences
# ============================================================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KAGEcryptor - GUY KOUAKOU | KAGEH@CK3R")
        self.resize(800, 600)
        self.settings = QSettings("KAGEcryptor", "Preferences")
        self.threadpool = QThreadPool()
        self.init_ui()
        self.load_theme()
    
    def init_ui(self):
        self.tabs = QTabWidget()
        self.text_tab = TextTab(self.settings)
        self.file_tab = FileTab(self.settings, self.threadpool)
        self.tabs.addTab(self.text_tab, "Texte")
        self.tabs.addTab(self.file_tab, "Fichiers/Images")
        self.setCentralWidget(self.tabs)
        
        # Menu pour la sélection du thème
        menubar = self.menuBar()
        settings_menu = menubar.addMenu("Paramètres")
        theme_action = QAction("Changer le thème", self)
        theme_action.triggered.connect(self.change_theme)
        settings_menu.addAction(theme_action)
    
    def change_theme(self):
        # Bascule entre thème clair et sombre
        current_theme = self.settings.value("theme", "light")
        new_theme = "dark" if current_theme == "light" else "light"
        self.settings.setValue("theme", new_theme)
        self.load_theme()
    
    def load_theme(self):
        theme = self.settings.value("theme", "light")
        if theme == "dark":
            self.setStyleSheet("""
                QMainWindow { background-color: #2b2b2b; color: #f0f0f0; }
                QTextEdit { background-color: #3c3c3c; color: #f0f0f0; }
                QLineEdit { background-color: #3c3c3c; color: #f0f0f0; }
                QLabel { color: #f0f0f0; }
                QPushButton { background-color: #555555; color: #f0f0f0; }
                QComboBox { background-color: #3c3c3c; color: #f0f0f0; }
                QMenuBar { background-color: #2b2b2b; color: #f0f0f0; }
                QMenu { background-color: #2b2b2b; color: #f0f0f0; }
            """)
        else:
            self.setStyleSheet("")  # thème par défaut
    
    def closeEvent(self, event):
        # Sauvegarde des préférences
        self.text_tab.save_preferences()
        self.file_tab.save_preferences()
        event.accept()


# ============================================================================
# Lancement de l'application
# ============================================================================

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

