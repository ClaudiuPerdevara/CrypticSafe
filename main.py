from re import match
from stat import FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM
import pyotp ,qrcode, io
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from cryptography.exceptions import InvalidTag
from database import *
from crypto import *
from datetime import *
import sys,re,os,ctypes,shutil
from pathlib import Path

BASE_VAULT_PATH = Path.cwd() / 'SafeVault'

FA_FONT_NAME = ""
def fa_icon(unicode_code):
    """Returnează un QIcon bazat pe caracterul Font Awesome dat."""
    font = QFont(FA_FONT_NAME)
    font.setPointSize(12)

    pixmap = QPixmap(24, 24)
    pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setFont(font)
    painter.setPen(QColor("#E0E0E0"))
    painter.drawText(pixmap.rect(), Qt.AlignCenter, unicode_code)
    painter.end()

    return QIcon(pixmap)

class ToggleSwitch(QCheckBox):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(60,28)

    def mousePressEvent(self, event):
        """ Suprascrie clicul pentru a schimba starea manual. """
        self.setChecked(not self.isChecked())
        event.accept()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        # Fundal
        rect = QRect(0, 0, self.width(), self.height())
        if self.isChecked():
            bg_color = QColor("#00A859")  # Verde (Activat)
        else:
            bg_color = QColor("#CC0000")  # Roșu (Dezactivat)

        p.setBrush(bg_color)
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(rect, 14, 14)  # Colțuri rotunde

        # Comutator (cercul)
        p.setBrush(Qt.white)
        if self.isChecked():
            p.drawEllipse(self.width() - 24, 2, 24, 24)  # Poziția "ON" (dreapta)
        else:
            p.drawEllipse(2, 2, 24, 24)  # Poziția "OFF" (stânga)

        p.end()

class TwoFactorPage(QWidget):
    """ Pagina care cere codul 2FA la login. """
    login_2fa_successful = pyqtSignal()
    login_2fa_failed = pyqtSignal()  # Semnal pentru a reveni la login

    def __init__(self):
        super().__init__()
        self.totp_secret = None

        main_layout = QVBoxLayout()
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setLayout(main_layout)

        form_widget = QWidget()
        form_widget.setMaximumWidth(350)
        main_layout.addWidget(form_widget)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        form_widget.setLayout(layout)

        self.info_label = QLabel("Open your authenticator app and enter the 6-digit code.")
        self.info_label.setAlignment(Qt.AlignCenter)
        self.info_label.setWordWrap(True)

        self.code_input = QLineEdit()
        self.code_input.setAlignment(Qt.AlignCenter)
        self.code_input.setMaxLength(6)
        # Setează fontul la o mărime mai mare
        font = self.code_input.font()
        font.setPointSize(18)
        self.code_input.setFont(font)

        self.message_label = QLabel('')
        self.message_label.setStyleSheet('color: red')
        self.message_label.setAlignment(Qt.AlignCenter)

        self.verify_button = QPushButton('Verify')
        self.verify_button.setMinimumWidth(300)

        self.cancel_button = QPushButton('Cancel')
        self.cancel_button.setMinimumWidth(300)

        layout.addWidget(self.info_label)
        layout.addWidget(self.code_input)
        layout.addWidget(self.message_label)
        layout.addSpacing(15)

        # Layout-uri pentru centrare butoane
        verify_btn_layout = QHBoxLayout()
        verify_btn_layout.addStretch()
        verify_btn_layout.addWidget(self.verify_button)
        verify_btn_layout.addStretch()
        layout.addLayout(verify_btn_layout)

        cancel_btn_layout = QHBoxLayout()
        cancel_btn_layout.addStretch()
        cancel_btn_layout.addWidget(self.cancel_button)
        cancel_btn_layout.addStretch()
        layout.addLayout(cancel_btn_layout)

        self.verify_button.clicked.connect(self.on_verify)
        self.cancel_button.clicked.connect(self.login_2fa_failed.emit)
        self.code_input.returnPressed.connect(self.on_verify)

    def set_secret(self, secret):
        """ Setează cheia secretă pentru verificare. """
        self.totp_secret = secret
        self.code_input.clear()
        self.message_label.clear()

    def on_verify(self):
        if not self.totp_secret:
            self.message_label.setText("Error: 2FA secret not set.")
            return

        code = self.code_input.text()
        totp = pyotp.TOTP(self.totp_secret)

        if totp.verify(code):
            print("2FA Login Successful")
            self.login_2fa_successful.emit()
        else:
            self.message_label.setText("Invalid code.")

class LoginPage(QWidget):
    login_successful = pyqtSignal(bytes, str, str,str)
    go_to_register = pyqtSignal()

    def __init__(self):
        super().__init__()

        main_layout = QVBoxLayout()
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setLayout(main_layout)

        form_widget = QWidget()
        form_widget.setMaximumWidth(500)
        main_layout.addWidget(form_widget)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        form_widget.setLayout(layout)


        self.message_label = QLabel('')
        self.message_label.setStyleSheet('color: red')
        layout.addWidget(self.message_label)

        self.username_label = QLabel('User: ')
        self.username_input = QLineEdit()


        self.password_label = QLabel('Password: ')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.returnPressed.connect(self.on_login_clicked)
        # FĂRĂ lățime maximă aici

        self.login_buton = QPushButton('Login')
        self.login_buton.clicked.connect(self.on_login_clicked)
        self.login_buton.setMinimumWidth(300)  # <-- Setează lățimea BUTOANELOR (mai mică)

        self.register_button = QPushButton('Register')
        self.register_button.setMinimumWidth(300)  # <-- Setează lățimea BUTOANELOR (mai mică)

        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)

        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)

        layout.addSpacing(15)

        # --- REPARAT: Cum centrăm butoanele mai înguste ---
        # Adăugăm fiecare buton într-un layout orizontal cu spații goale

        login_btn_layout = QHBoxLayout()
        login_btn_layout.addStretch()  # Spațiu gol stânga
        login_btn_layout.addWidget(self.login_buton)
        login_btn_layout.addStretch()  # Spațiu gol dreapta
        layout.addLayout(login_btn_layout)  # Adaugă layout-ul cu butonul centrat

        register_btn_layout = QHBoxLayout()
        register_btn_layout.addStretch()
        register_btn_layout.addWidget(self.register_button)
        register_btn_layout.addStretch()
        layout.addLayout(register_btn_layout)
        # -------------------------------------------------

        self.register_button.clicked.connect(self.go_to_register.emit)


    def on_login_clicked(self):
        username = self.username_input.text()
        password = self.password_input.text()
        self.message_label.setText('')
        print(f"Login attempt with user: {username}")
        user_data = get_login_data(username)

        if user_data is None:
            self.message_label.setText('Wrong user/password')
            self.password_input.clear()
            print('Login failed!')
            return

        salt, encrypt_data_blob, vault_path, totp_secret = user_data

        try:
            kek = generate_key_from_password(password.encode('utf-8'), salt)
            dek = decrypt_data(kek, encrypt_data_blob)  # încerc parola
            print('Login successful!')
            self.username_input.clear()
            self.password_input.clear()

            # asigură-te că vault_path e string
            self.login_successful.emit(dek, str(vault_path), username, totp_secret)
        except InvalidTag:  # dacă nu a mers dek-ul
            self.message_label.setText('Wrong user/password')
            self.password_input.clear()
            print('Login failed!')
        except Exception as e:
            self.message_label.setText(f"Error: {e}")
            self.password_input.clear()
            print('Login failed!', e)

class FileListWidget(QTreeWidget): # <-- SCHIMBARE: QTreeWidget
    def __init__(self, main_page, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.main_page = main_page
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)

        # --- AICI ADAUGĂM COLOANELE ---
        self.setHeaderLabels(["Name", "Size", "Date Modified"])
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch) # Numele ia spațiul maxim
        self.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents) # Mărimea se ajustează
        self.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents) # Data se ajustează

        # --- AICI ASCUNDEM ASPECTUL DE ARBORE ---
        self.setRootIsDecorated(False) # Ascunde butoanele +/-
        self.setIndentation(0) # Elimină spațiul de dinaintea iconiței

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() or event.mimeData().hasFormat("application/x-qabstractitemmodeldatalist"):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        target_item = self.itemAt(event.pos())
        if target_item:
            # --- MODIFICAT: Luăm textul din coloana 0 ---
            target_path = self.main_page.current_vault_path / target_item.text(0)
            if target_path.is_file():
                event.ignore()
                return
        if event.mimeData().hasUrls() or event.mimeData().hasFormat("application/x-qabstractitemmodeldatalist"):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        target_path = self.main_page.current_vault_path
        target_item = self.itemAt(event.pos())

        if target_item:
            potential_path = self.main_page.current_vault_path / target_item.text(0)
            if potential_path.is_dir():
                target_path = potential_path

        if not self.main_page.dek:
            QMessageBox.warning(self.main_page, "Error", "Date lipsa. Nu se poate adauga.")
            event.ignore()
            return

        try:
            if event.mimeData().hasUrls():
                event.acceptProposedAction()
                for url in event.mimeData().urls():
                    source_path = Path(url.toLocalFile())
                    if source_path.is_file():
                        self.main_page.add_file_from_path(str(source_path), target_path, move_file=True)
                    elif source_path.is_dir():
                        try:
                            self.main_page.add_folder(source_path, target_path)
                            shutil.rmtree(source_path)
                        except Exception as e:
                            QMessageBox.critical(self.main_page, "Error Add folder", str(e))
                self.main_page.load_vault_files()

            elif event.mimeData().hasFormat("application/x-qabstractitemmodeldatalist"):
                encoded_data = event.mimeData().data("application/x-qabstractitemmodeldatalist")
                data_stream = QDataStream(encoded_data, QIODevice.ReadOnly)
                source_name = None
                while not data_stream.atEnd():
                    row = data_stream.readInt32()
                    col = data_stream.readInt32()  # Citim și coloana
                    data_items = data_stream.readInt32()

                    for i in range(data_items):
                        role = data_stream.readInt32()
                        value = data_stream.readQVariant()

                        # --- AICI ESTE CORECTURA ---
                        # Verificăm dacă datele vin din coloana 0 (Nume)
                        if col == 0 and role == Qt.ItemDataRole.DisplayRole:
                            source_name = value
                            break
                    if source_name:  # Dacă am găsit numele, ieșim
                        break

                if not source_name:
                    event.ignore()
                    return

                source_path = self.main_page.current_vault_path / source_name
                destination_path = target_path / source_name

                if source_path == destination_path or destination_path.exists():
                    print("Sursa e aceeasi cu locatia")
                    event.ignore()
                    return
                source_path.rename(destination_path)
                self.main_page.load_vault_files()
                event.acceptProposedAction()
            else:
                event.ignore()
        except Exception as e:
            QMessageBox.critical(self.main_page, "Eroare la drop", str(e))
            event.ignore()

class MainPage(QMainWindow):
    do_logout = pyqtSignal()
    open_settings = pyqtSignal()

    def __init__(self):
        super().__init__()

        self.dek = None
        self.root_vault_path = None
        self.current_vault_path = None
        self.clipboard_data = None

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(8)

        # toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(15)
        toolbar.setContentsMargins(20, 0, 20, 0)


        # butoane principale
        self.back_button = QPushButton("Back")
        self.back_button.setEnabled(False)
        self.back_button.setMinimumHeight(36)
        self.back_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        toolbar.addWidget(self.back_button)

        self.add_button = QPushButton(fa_icon("\uf055"), "Add")  # Plus
        self.export_button = QPushButton(fa_icon("\uf56e"), "Export")  # Export
        self.delete_button = QPushButton(fa_icon("\uf2ed"), "Delete")  # Trash
        self.logout_button = QPushButton(fa_icon("\uf2f5"), "Logout")  # Logout
        self.settings_button = QPushButton("\uf013")  # Iconița Gear
        self.settings_button.setObjectName("toolbarButton")
        self.settings_button.setToolTip("Settings")

        # Am pus butonul de settings la final
        toolbar.addStretch()
        for btn in [self.add_button, self.export_button, self.delete_button, self.logout_button]:
            btn.setMinimumHeight(36)
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            toolbar.addWidget(btn)
        toolbar.addStretch()

        self.settings_button.setMinimumHeight(36)
        self.settings_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.settings_button.setFixedWidth(45)
        toolbar.addWidget(self.settings_button)
        self.settings_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.settings_button.setFixedWidth(45)
        toolbar.addSpacing(-80)
        toolbar.addWidget(self.settings_button)

        # file list (acum este un QTreeWidget)
        self.file_list = FileListWidget(self)
        self.file_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_list.customContextMenuRequested.connect(self.on_context_menu)

        # main layout
        main_layout.addLayout(toolbar)
        self.path_bar = QLineEdit()
        self.path_bar.setReadOnly(True)
        self.path_bar.setStyleSheet("background-color: #2E2E2E; color: #CCCCCC; border: none; padding: 4px;")
        main_layout.addWidget(self.path_bar)
        main_layout.addWidget(self.file_list)

        # conectare butoane
        self.back_button.clicked.connect(self.on_back_clicked)
        self.add_button.clicked.connect(self.on_add_menu_show)
        self.logout_button.clicked.connect(self.do_logout.emit)
        self.export_button.clicked.connect(self.on_export_clicked)
        self.delete_button.clicked.connect(self.on_delete_file_clicked)
        self.settings_button.clicked.connect(self.open_settings.emit)

    def load_user_data(self, dek, vault_path, username):
        self.dek = dek
        self.root_vault_path = Path(vault_path)
        self.current_vault_path = Path(vault_path)
        self.load_vault_files()

    def on_back_clicked(self):
        if self.current_vault_path and self.root_vault_path != self.current_vault_path:
            self.current_vault_path = self.current_vault_path.parent
            self.load_vault_files()

    def on_delete_file_clicked(self):
        item = self.file_list.currentItem()
        if not item:
            return
        filename = item.text(0)  # <-- MODIFICAT
        vault_file = self.current_vault_path / filename

        reply = QMessageBox.question(
            self,
            "Delete confirmation",
            f"Are you sure you want to delete {filename}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                if vault_file.is_dir():
                    shutil.rmtree(vault_file)
                elif vault_file.is_file():
                    vault_file.unlink()
                self.load_vault_files()
                print(f"Fișierul/folderul {filename} a fost șters.")
            except Exception as e:
                QMessageBox.critical(self, "Eroare", f"Nu s-a putut șterge fișierul: {e}")

    def add_file_from_path(self, filepath, destination_folder, move_file=False):
        if not self.dek:
            QMessageBox.warning(self, "Eroare", "Date lipsă")
            return False

        source_path = Path(filepath)
        if not source_path.exists():
            QMessageBox.warning(self, "Eroare", "Fișier sursă inexistent")
            return False

        filename = source_path.name
        dest_path = destination_folder / filename

        if dest_path.exists():
            if dest_path.is_dir():
                QMessageBox.warning(self, "Error", "A folder with the same name already exists.")
                return False
            if move_file:
                print(f"Fișierul '{filename}' există deja. Ignorat (move).")
                return False

            reply = QMessageBox.question(self, "Fișier existent",
                                         f"Fișierul '{filename}' există deja. Suprascrii?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                return False

        try:
            with source_path.open('rb') as f:
                file_data = f.read()
            encrypted_blob = encrypt_data(self.dek, file_data)
            with dest_path.open('wb') as f:
                f.write(encrypted_blob)
            print(f"Fișierul {filename} a fost adăugat și criptat.")

            if move_file:
                try:
                    source_path.unlink()
                    print(f"Fișierul sursă {source_path} a fost șters.")
                except Exception as e:
                    QMessageBox.warning(self, "Eroare ștergere", f"Nu s-a putut șterge fișierul sursă: {e}")
            return True
        except Exception as e:
            QMessageBox.critical(self, "Eroare", f"Nu s-a putut adăuga fișierul: {e}")
            return False

    def add_folder(self, source_folder, vault_destination_folder):
        try:
            source_folder = Path(source_folder)
            new_vault_folder = vault_destination_folder / source_folder.name

            if new_vault_folder.exists() and new_vault_folder.is_file():
                raise Exception(f"Un fișier cu numele '{source_folder.name}' există deja.")

            new_vault_folder.mkdir(parents=True, exist_ok=True)
            print(f"Procesare folder: {source_folder.name}")

            for item in source_folder.iterdir():
                if item.is_file():
                    filename = item.name
                    dest_path = new_vault_folder / filename
                    if dest_path.exists():
                        print(f"Fișierul '{filename}' există deja. Ignorat.")
                        continue
                    with item.open('rb') as f:
                        file_data = f.read()
                    encrypted_data = encrypt_data(self.dek, file_data)
                    with dest_path.open('wb') as f:
                        f.write(encrypted_data)
                elif item.is_dir():
                    self.add_folder(item, new_vault_folder)

        except Exception as e:
            print(f"EROARE la procesarea folderului {source_folder}: {e}")
            raise Exception(f"Nu s-a putut adăuga {source_folder}:\n{e}")

    def load_vault_files(self):
        self.file_list.clear()
        if not self.current_vault_path or not self.current_vault_path.exists():
            print(f"Vault dir doesn't exist {self.current_vault_path}")
            return

        is_at_root = (self.current_vault_path == self.root_vault_path)
        self.back_button.setEnabled(not is_at_root)

        if is_at_root:
            display_path = "\\"
        else:
            try:
                relative_path = self.current_vault_path.relative_to(self.root_vault_path)
                display_path = f"\\{str(relative_path).replace('/', '\\')}"
            except ValueError:
                display_path = "\\"
        self.path_bar.setText(display_path)

        folder_icon = self.style().standardIcon(QStyle.SP_DirIcon)
        file_icon = self.style().standardIcon(QStyle.SP_FileIcon)

        folders = []
        files = []

        try:
            for item_path in self.current_vault_path.iterdir():
                stat_info = item_path.stat()
                date_mod = datetime.fromtimestamp(stat_info.st_mtime).strftime('%d-%m-%Y %H:%M')

                if item_path.is_dir():
                    tree_item = QTreeWidgetItem([item_path.name, "<DIR>", date_mod])
                    tree_item.setIcon(0, folder_icon)
                    folders.append(tree_item)

                elif item_path.is_file():
                    size_kb = stat_info.st_size / 1024
                    size_str = f"{size_kb:.1f} KB"
                    if size_kb < 1:  # Afișează bytes dacă e prea mic
                        size_str = f"{stat_info.st_size} B"

                    tree_item = QTreeWidgetItem([item_path.name, size_str, date_mod])
                    tree_item.setIcon(0, file_icon)

                    # Aliniază textul la dreapta pentru mărime
                    tree_item.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
                    files.append(tree_item)

            # Adaugă folderele, apoi fișierele (sortate)
            self.file_list.addTopLevelItems(sorted(folders, key=lambda x: x.text(0)))
            self.file_list.addTopLevelItems(sorted(files, key=lambda x: x.text(0)))

        except Exception as e:
            print(f"Eroare la citirea fișierelor: {e}")
            QMessageBox.warning(self, "Eroare", f"Nu s-au putut încărca fișierele: {e}")

    def view_decrypted_in_app(self, item, column):
        if not item:
            return

        filename = item.text(0)  # <-- MODIFICAT
        vault_file = self.current_vault_path / filename

        if vault_file.is_dir():
            self.current_vault_path = vault_file
            self.load_vault_files()
            return

        try:
            with vault_file.open('rb') as f:
                encrypted = f.read()
            decrypted = decrypt_data(self.dek, encrypted)

            pixmap = QPixmap()
            if pixmap.loadFromData(decrypted):
                dialog = QDialog(self)
                dialog.setWindowTitle(f"{filename}")
                dialog.setStyleSheet(self.styleSheet())
                layout = QVBoxLayout(dialog)
                label = QLabel()
                label.setPixmap(pixmap.scaled(800, 600, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                label.setAlignment(Qt.AlignCenter)
                layout.addWidget(label)
                dialog.exec_()
            else:
                text = decrypted.decode('utf-8', errors='ignore')
                dialog = QDialog(self)
                dialog.setWindowTitle(f"{filename}")
                dialog.setMinimumSize(900, 600)
                dialog.setStyleSheet(self.styleSheet().replace("14px", "12px"))  # Font mai mic

                v = QVBoxLayout(dialog)
                text_edit = QTextEdit()
                text_edit.setPlainText(text)
                v.addWidget(text_edit)
                btn_layout = QHBoxLayout()
                btn_save = QPushButton("💾 Save")
                btn_cancel = QPushButton("❌ Cancel")
                btn_layout.addStretch()
                btn_layout.addWidget(btn_save)
                btn_layout.addWidget(btn_cancel)
                v.addLayout(btn_layout)

                def save_changes():
                    new_text = text_edit.toPlainText().encode('utf-8')
                    new_encrypted = encrypt_data(self.dek, new_text)
                    with vault_file.open('wb') as f:
                        f.write(new_encrypted)
                    dialog.accept()

                btn_save.clicked.connect(save_changes)
                btn_cancel.clicked.connect(dialog.reject)
                dialog.exec_()
        except Exception as e:
            QMessageBox.critical(self, "Eroare", f"Eroare la deschidere:\n{e}")

    def open_add_file_dialog(self):
        if not self.dek or not self.current_vault_path:
            QMessageBox.warning(self, "Eroare", "Date lipsa")
            return

        # Permite selectarea mai multor fișiere
        file_paths, _ = QFileDialog.getOpenFileNames(self,
                                                     "Select File(s)", "", "All Files (*.*)")
        if not file_paths:
            return

        success_count = 0
        for file_path_str in file_paths:
            success = self.add_file_from_path(file_path_str, self.current_vault_path, move_file=False)
            if success:
                success_count += 1

        if success_count > 0:
            self.load_vault_files()

    def open_add_folder_dialog(self, move=False):
        """ Funcție pentru butonul de meniu Add Folder """
        if not self.dek or not self.current_vault_path:
            QMessageBox.warning(self, "Eroare", "Date lipsa")
            return

        folder = QFileDialog.getExistingDirectory(self, "Select folder to add")
        if folder:
            try:
                self.add_folder(Path(folder), self.current_vault_path)
                if move:  # doar dacă vrem să mutăm sursa
                    shutil.rmtree(folder)
                self.load_vault_files()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def on_add_menu_show(self):
        menu = QMenu(self)
        menu.setFont(QFont(FA_FONT_NAME, 14))  # Setăm fontul de iconițe

        add_file = menu.addAction("\uf15b  Add File(s)...")  # Iconiță Fișier
        add_folder = menu.addAction("\uf07c  Add Folder (Move)...")  # Iconiță Folder

        button_pos = self.add_button.mapToGlobal(QPoint(0, self.add_button.height()))
        action = menu.exec_(button_pos)

        if action == add_file:
            self.open_add_file_dialog()
        elif action == add_folder:
            # Apelăm funcția corectă (dacă ai redenumit-o)
            self.open_add_folder_dialog(move=True)  # Specificăm că mutăm

    def export_folder_recursively(self, source_vault_folder, dest_filesystem_folder):
        """
        Funcție recursivă care decriptează și copiază
        conținutul unui folder din vault în sistemul de fișiere.
        """
        for item in source_vault_folder.iterdir():
            if item.is_file():
                # Este fișier: decriptează și copiază
                print(f"Exporting file: {item.name}")
                dest_file_path = dest_filesystem_folder / item.name

                with item.open('rb') as f_in:
                    encrypted_data = f_in.read()

                decrypted_data = decrypt_data(self.dek, encrypted_data)

                with dest_file_path.open('wb') as f_out:
                    f_out.write(decrypted_data)

            elif item.is_dir():
                # Este folder: creează-l și continuă recursiv
                print(f"Creating sub-folder: {item.name}")
                new_dest_folder = dest_filesystem_folder / item.name
                new_dest_folder.mkdir(exist_ok=True)

                # Apel recursiv
                self.export_folder_recursively(item, new_dest_folder)

    def on_export_clicked(self):
        selected_item = self.file_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Eroare", "Please select a file/folder to export.")
            return

        filename = selected_item.text(0)
        source_path = self.current_vault_path / filename

        # --- LOGICĂ NOUĂ: Verifică dacă e fișier sau folder ---

        if source_path.is_file():
            # --- Logica existentă for FIȘIERE ---
            dest_path_str, _ = QFileDialog.getSaveFileName(self, "Export File", filename, "All Files (*.*)")
            if not dest_path_str:
                return
            try:
                with source_path.open("rb") as f_in:
                    encrypted_data = f_in.read()
                decrypted_data = decrypt_data(self.dek, encrypted_data)
                with open(dest_path_str, "wb") as f_out:
                    f_out.write(decrypted_data)
                QMessageBox.information(self, "Succes", "Fișierul a fost exportat cu succes.")
            except InvalidTag:
                QMessageBox.information(self, "Eroare", "Decriptare eșuată (cheie invalidă).")
            except Exception as e:
                QMessageBox.information(self, "Eroare", f"Exportul a eșuat: {e}")

        elif source_path.is_dir():
            # --- Logica NOUĂ for FOLDERE ---
            dest_folder_str = QFileDialog.getExistingDirectory(self, "Selectează un folder pentru export")
            if not dest_folder_str:
                return  # Utilizatorul a anulat

            try:
                # Creăm un folder nou cu același nume la destinație
                export_target_path = Path(dest_folder_str) / filename
                export_target_path.mkdir(exist_ok=True)

                # Începem procesul recursiv de decriptare
                self.export_folder_recursively(source_path, export_target_path)

                QMessageBox.information(self, "Succes", f"Folderul '{filename}' a fost exportat cu succes.")
            except Exception as e:
                QMessageBox.critical(self, "Eroare Export Folder", f"A apărut o eroare: {e}")

    def on_context_menu(self, pos):
        item = self.file_list.itemAt(pos)
        menu = QMenu(self.file_list)
        menu.setFont(QFont('Consolas', 11))

        paste_action = QAction(fa_icon("\uf0ea"), "Paste", self)
        paste_action.setEnabled(self.clipboard_data is not None)
        menu.addAction(paste_action)

        if item:
            menu.addSeparator()
            copy_action = QAction(fa_icon("\uf0c5"), "Copy", self)
            cut_action = QAction(fa_icon("\uf0c4"), "Cut", self)
            rename_action = QAction(fa_icon("\uf044"), "Rename", self)
            properties_action = QAction(fa_icon("\uf05a"), "Properties", self)
            delete_action = QAction(fa_icon("\uf2ed"), "Delete", self)

            for a in [copy_action, cut_action, rename_action, properties_action, delete_action]:
                menu.addAction(a)

            action = menu.exec_(self.file_list.mapToGlobal(pos))

            if action == rename_action:
                self.on_rename_item(item)
            elif action == properties_action:
                self.on_properties_item(item)
            elif action == delete_action:
                self.on_delete_file_clicked()
            elif action == copy_action:
                self.on_copy_item(item)
            elif action == cut_action:
                self.on_cut_item(item)
            elif action == paste_action:
                self.on_paste_item(item)
        else:
            menu.addSeparator()
            refresh_action = QAction(fa_icon("\uf021"), "Refresh", self)
            menu.addAction(refresh_action)
            action = menu.exec_(self.file_list.mapToGlobal(pos))
            if action == refresh_action:
                self.load_vault_files()
            elif action == paste_action:
                self.on_paste_item(None)

    def on_copy_item(self, item):
        path = self.current_vault_path / item.text(0)  # <-- MODIFICAT
        self.clipboard_data = ("copy", path)
        print(f"Copied: {path}")

    def on_cut_item(self, item):
        path = self.current_vault_path / item.text(0)  # <-- MODIFICAT
        self.clipboard_data = ("cut", path)
        print(f"Cut: {path}")

    def on_rename_item(self, item):
        old_name = item.text(0)  # <-- MODIFICAT
        old_path = self.current_vault_path / old_name

        new_name, ok = QInputDialog.getText(self, "Rename Item", "Enter new name:", QLineEdit.Normal, old_name)
        if ok and new_name and new_name != old_name:
            new_path = self.current_vault_path / new_name
            if new_path.exists():
                QMessageBox.warning(self, "Error", "A file or folder exists with this name.")
                return
            try:
                old_path.rename(new_path)
                self.load_vault_files()
            except Exception as e:
                QMessageBox.critical(self, "Eroare", f"Nu s-a putut redenumi: {e}")

    def on_properties_item(self, item):
        name = item.text(0)  # <-- MODIFICAT
        path = self.current_vault_path / name
        try:
            stat_info = path.stat()
            size = stat_info.st_size
            date_mod_str = datetime.fromtimestamp(stat_info.st_mtime).strftime('%d-%m-%Y %H:%M:%S')

            if path.is_dir():
                item_count = len(list(path.iterdir()))
                QMessageBox.information(self, f"Properties: {name}",
                                        f"Nume: {name}\nTip: Folder\nConține: {item_count} elemente\nModificat: {date_mod_str}")
            else:
                size_kb = size / 1024
                QMessageBox.information(self, f"Properties: {name}",
                                        f"Nume: {name}\nTip: Fișier criptat\nMărime: {size} bytes ({size_kb:.2f} KB)\nModificat: {date_mod_str}")
        except Exception as e:
            QMessageBox.critical(self, "Eroare", f"Nu s-au putut obține proprietățile: {e}")

    def on_paste_item(self, target_item):
        if not self.clipboard_data:
            return

        action, source_path = self.clipboard_data
        dest_folder = self.current_vault_path

        if target_item:
            potential_path = self.current_vault_path / target_item.text(0)  # <-- MODIFICAT
            if potential_path.is_dir():
                dest_folder = potential_path

        dest_path = dest_folder / source_path.name
        if source_path == dest_path:
            print("Cannot paste on self.")
            return

        copy_num = 1
        original_dest_path = dest_path
        while dest_path.exists():
            if source_path.is_file():
                new_name = f"{original_dest_path.stem} (copy {copy_num}){original_dest_path.suffix}"
            else:
                new_name = f"{original_dest_path.name} (copy {copy_num})"
            dest_path = dest_folder / new_name
            copy_num += 1

        try:
            if action == "copy":
                print(f"Copying {source_path} to {dest_path}")
                if source_path.is_file():
                    shutil.copyfile(source_path, dest_path)
                elif source_path.is_dir():
                    shutil.copytree(source_path, dest_path)
            elif action == "cut":
                print(f"Moving {source_path} to {dest_path}")
                source_path.rename(dest_path)
                self.clipboard_data = None

            self.load_vault_files()
        except Exception as e:
            QMessageBox.critical(self, "Eroare la Lipire", f"Nu s-a putut finaliza operațiunea: {e}")

class RegisterPage(QMainWindow):
    go_to_login = pyqtSignal()

    def reset_fields(self):
        try:
            self.username_input.clear()
            self.password_input.clear()
            self.confirm_input.clear()
            self.strength_bar.setValue(0)
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: transparent; }")
            self.message_label.clear()
        except Exception:
            pass

    def __init__(self):
        super().__init__()
        layout = QGridLayout()
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QGridLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(10)

        self.username_label = QLabel('User:')
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choose an username")

        self.password_label = QLabel('Password:')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.strength_bar = QProgressBar()
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setMaximum(4)

        self.confirm_label = QLabel('Confirm password:')
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.message_label = QLabel('')
        self.message_label.setStyleSheet('color: red')

        self.register_button = QPushButton("Register")
        self.back_button = QPushButton("Back")

        layout.addWidget(self.username_label, 0, 0)
        layout.addWidget(self.username_input, 0, 1)
        layout.addWidget(self.password_label, 1, 0)
        layout.addWidget(self.password_input, 1, 1)

        # --- REPARAT: Ordinea corectă a layout-ului ---
        self.strength_bar.setMaximumHeight(15)
        layout.addWidget(self.strength_bar, 2, 1)  # Bara e la rândul 2
        layout.addWidget(self.confirm_label, 3, 0)  # Confirm e la rândul 3
        layout.addWidget(self.confirm_input, 3, 1)  # Confirm e la rândul 3
        layout.addWidget(self.message_label, 4, 0, 1, 2)  # Mesajul e la rândul 4
        layout.addWidget(self.register_button, 5, 1)  # Butonul e la rândul 5

        # --- Buton Back în colțul stâng sus ---
        # --- Buton Back în colțul stâng jos ---
        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(self.back_button, alignment=Qt.AlignLeft)
        bottom_layout.addStretch()
        bottom_layout.setContentsMargins(20, 10, 20, 10)

        main_layout = QVBoxLayout()
        main_layout.addLayout(layout)
        main_layout.addLayout(bottom_layout)

        central_widget.setLayout(main_layout)

        self.register_button.clicked.connect(self.on_register_clicked)
        self.back_button.clicked.connect(self.go_to_login.emit)
        self.password_input.textChanged.connect(self.update_password_strength)

    def update_password_strength(self, password):
        score = 0
        if len(password) > 0: score = 1
        if len(password) >= 8: score += 1
        if re.search(r"[a-zA-Z]", password) and re.search(r"\d", password): score += 1
        if re.search(r"[!@#$%^&*(),.?:{}|<>_]", password): score += 1

        self.strength_bar.setValue(score)

        if score == 1: color = "#CC0000"  # Roșu
        elif score == 2: color = "#FF8C00"  # Portocaliu
        elif score == 3: color = "#E0E000"  # Galben
        elif score == 4: color = "#00A859"  # Verde
        else: color = "transparent"  # Gol

        # Setează stilul doar pentru "chunk" (partea colorată)
        self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: %s; border-radius: 5px; }" % color)

    def on_register_clicked(self):
        username = self.username_input.text()
        password = self.password_input.text()
        confirm = self.confirm_input.text()

        self.message_label.setText('')
        self.message_label.setStyleSheet('color: red')

        if not username or not password:
            self.message_label.setText('User and password cannot be empty')
            return
        if password != confirm:
            self.message_label.setText('Passwords don\'t match')
            return
        if self.strength_bar.value() < 2:
            self.message_label.setText('Password is too weak.')
            return

        try:
            if check_user(username):
                self.message_label.setText('User exists!')
                return
            salt = generate_salt()
            dek = generate_new_dek()
            kek = generate_key_from_password(password.encode('utf-8'), salt)
            encrypted_dek = encrypt_data(kek, dek)
            vault_path = BASE_VAULT_PATH / f"{username}_vault"
            vault_path.mkdir(parents=True, exist_ok=True)
            result = create_user(username, salt, encrypted_dek, str(vault_path))
            if result:
                print(f"User: {username} registered!")
                self.username_input.clear()
                self.password_input.clear()
                self.confirm_input.clear()
                self.message_label.setStyleSheet('color: green')
                self.message_label.setText('Account created! Go to login!')
            else:
                self.message_label.setStyleSheet('color: red')
                self.message_label.setText('Error')
        except Exception as e:
            self.message_label.setText(f"Error: {e}")
            print(f"Error: {e}")

class AppContainer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_username = None
        self.current_dek = None
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setObjectName("MainWindow")

        self.stack = QStackedWidget()

        self.login_page = LoginPage()
        self.main_page = MainPage()
        self.register_page = RegisterPage()
        self.two_factor_page = TwoFactorPage()

        self.stack.addWidget(self.login_page)
        self.stack.addWidget(self.main_page)
        self.stack.addWidget(self.register_page)
        self.stack.addWidget(self.two_factor_page)

        self.control_buttons_layout = QHBoxLayout()
        self.control_buttons_layout.setContentsMargins(15, 0, 10, 0)
        self.control_buttons_layout.setSpacing(5)

        self.window_title_label = QLabel("Cryptic Safe")
        self.window_title_label.setObjectName("windowTitleLabel")
        self.control_buttons_layout.addWidget(self.window_title_label)
        self.control_buttons_layout.addStretch()

        self.minimize_button = QPushButton("−")
        self.close_button = QPushButton("✕")
        self.minimize_button.setObjectName("controlButton")
        self.close_button.setObjectName("controlButton")

        self.minimize_button.clicked.connect(self.showMinimized)
        self.close_button.clicked.connect(self.close)
        self.control_buttons_layout.addWidget(self.minimize_button)
        self.control_buttons_layout.addWidget(self.close_button)

        self.main_app_layout = QVBoxLayout()
        self.main_app_layout.setContentsMargins(3, 3, 3, 3)  # Margin for border
        self.main_app_layout.setSpacing(0)
        self.main_app_layout.addLayout(self.control_buttons_layout)
        self.main_app_layout.addWidget(self.stack)

        temp_widget = QWidget()
        temp_widget.setObjectName("mainContentArea")
        temp_widget.setLayout(self.main_app_layout)
        self.setCentralWidget(temp_widget)

        # --- AICI ESTE BLOCUL QSS COMPLET ȘI CORECTAT ---
        self.setStyleSheet("""
            #mainContentArea {
                border: 2px solid #B30000; /* Roșu intens */
                border-radius: 10px;
            }

            QWidget {
                background-color: #1C1B1B;
                color: #F2F2F2;
                font-family: 'Consolas';
                font-size: 14px;
                border: none;
            }

            QLabel#windowTitleLabel {
                color: #F2F2F2;
                font-weight: bold;
                font-size: 14px;
            }

            QLineEdit, QTextEdit {
                background-color: #2A2A2A;
                color: #FFFFFF;
                border: 2px solid #B30000;
                border-radius: 6px;
                padding: 6px;
            }

            QPushButton {
                background-color: #A61919;
                color: #FFFFFF;
                border-radius: 8px;
                padding: 6px 14px;
                font-size: 15px;
                border: 1px solid #7A0E0E;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #CC1F1F;
            }

            QPushButton:pressed {
                background-color: #800000;
            }

            QPushButton:disabled {
                background-color: #4A4A4A;
                color: #AAAAAA;
            }

            QTreeWidget {
                background-color: #2A2A2A;
                border: 2px solid #B30000;
                border-radius: 8px;
                color: #E0E0E0;
            }

            QTreeWidget::item:selected {
                background-color: #CC1F1F;
                color: #FFFFFF;
            }

            QHeaderView::section {
                background-color: #2A2A2A;
                color: #E0E0E0;
                padding: 4px;
                border: none;
                border-bottom: 2px solid #B30000;
            }

            QMenu {
                background-color: #2A2A2A;
                border: 2px solid #B30000;
                border-radius: 8px;
                padding: 5px;
                color: #E0E0E0;
            }

            QMenu::item {
                padding: 8px 25px 8px 20px;
                border-radius: 4px;
            }

            QMenu::item:selected {
                background-color: #B30000;
                color: #FFFFFF;
            }

            QProgressBar {
                border: 1px solid #B30000;
                border-radius: 5px;
                background-color: #2A2A2A;
            }

            QPushButton#controlButton {
                background-color: transparent;
                color: #E0E0E0;
                border: none;
                font-size: 18px;
                padding: 0 8px;
                min-width: 30px;
                min-height: 25px;
            }

            QPushButton#controlButton:hover {
                background-color: #B30000;
            }

            QPushButton#controlButton[text="✕"]:hover {
                background-color: #E60000;
            }
            
            /* --- Stil pentru butonul de Setări --- */
                    QPushButton[text="\uf013"] {
                    
                        font-family: "Font Awesome 7 Free Solid";
                        font-size: 16px;
                        background-color: #A61919;
                        border: 1px solid #7A0E0E;
                    }
                    QPushButton[text="\uf013"]:hover {
                        background-color: #CC1F1F;
                        border: 1px solid #CC1F1F;
                    }
                    QPushButton[text="\uf013"]:pressed {
                        background-color: #800000;
                    }
                    /* --- Stil pentru ToggleSwitch (QCheckBox) --- */
            QCheckBox {
                spacing: 0px;
            }
            QCheckBox::indicator {
                width: 0px; /* Ascunde căsuța default */
                height: 0px;
            }
        """)

        self.setWindowTitle('Cryptic Safe')
        self.setMinimumSize(800, 500)
        self.setMaximumSize(1920, 1200)

        self.login_page.login_successful.connect(self.handle_login_step_one)
        self.register_page.go_to_login.connect(self.show_login_page)
        self.login_page.go_to_register.connect(self.show_register_page)
        self.main_page.do_logout.connect(self.show_login_page)
        self.main_page.file_list.itemDoubleClicked.connect(self.main_page.view_decrypted_in_app)
        self.main_page.open_settings.connect(self.show_settings_page)
        self.two_factor_page.login_2fa_successful.connect(self.show_main_app)
        self.two_factor_page.login_2fa_failed.connect(self.show_login_page)

    def handle_login_step_one(self, dek, vault_path, username, totp_secret):
        """ Parola a fost corectă. Verifică dacă 2FA este activat. """
        self.temp_dek = dek
        self.temp_vault_path = vault_path
        self.temp_username = username

        if totp_secret:
            # 2FA este activat. Mergi la pagina 2FA.
            self.two_factor_page.set_secret(totp_secret)
            self.stack.setCurrentIndex(3)  # Indexul paginii 2FA
            self.window_title_label.setText("Verify 2FA")
        else:
            self.show_main_app()

    def show_main_app(self):

        dek = self.temp_dek
        vault_path = self.temp_vault_path
        username = self.temp_username

        self.stack.setCurrentIndex(1)
        self.current_username = username
        self.current_dek = dek
        self.window_title_label.setText(f"Safe - User: {username}")
        self.main_page.load_user_data(dek, vault_path, username)

        self.temp_dek = None
        self.temp_vault_path = None
        self.temp_username = None

    def show_register_page(self):
        self.stack.setCurrentIndex(2)
        self.register_page.reset_fields()
        self.window_title_label.setText("Register")

    def show_login_page(self):
        self.login_page.password_input.clear()
        self.login_page.username_input.clear()
        self.login_page.message_label.clear()
        self.stack.setCurrentIndex(0)
        self.window_title_label.setText("Login")

        self.temp_dek = None
        self.temp_vault_path = None
        self.temp_username = None

    def show_settings_page(self):
        if self.current_username and self.current_dek:
            # Creează dialogul și îi dă 'self' ca părinte pentru stil
            dialog = SettingsDialog(self.current_username, self.current_dek, self)
            dialog.exec_()  # Îl arată modal (blochează fereastra principală)
        else:
            QMessageBox.warning(self, "Error", "User data not loaded correctly.")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            if event.pos().y() < self.control_buttons_layout.sizeHint().height():
                self.old_pos = event.globalPos()
                self.dragging = True
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if hasattr(self, 'dragging') and self.dragging:
            delta = event.globalPos() - self.old_pos
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self.old_pos = event.globalPos()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            if hasattr(self, 'dragging'):
                self.dragging = False
        super().mouseReleaseEvent(event)

class ChangePasswordDialog(QDialog):
    """ Fereastra dedicată doar pentru schimbarea parolei. """

    def __init__(self, username, dek, parent=None):
        super().__init__(parent)
        self.username = username
        self.dek = dek

        self.setWindowTitle("Change Password")
        self.setMinimumWidth(400)
        self.setStyleSheet(parent.styleSheet())

        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        self.current_pass_label = QLabel("Current Password:")
        self.current_pass_input = QLineEdit()
        self.current_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.current_pass_label)
        layout.addWidget(self.current_pass_input)

        self.new_pass_label = QLabel("New Password:")
        self.new_pass_input = QLineEdit()
        self.new_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.new_pass_label)
        layout.addWidget(self.new_pass_input)

        self.strength_bar = QProgressBar()
        self.strength_bar.setValue(0)
        self.strength_bar.setMaximumHeight(15)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setMaximum(4)
        layout.addWidget(self.strength_bar)
        self.new_pass_input.textChanged.connect(self.update_password_strength)

        self.confirm_pass_label = QLabel("Confirm New Password:")  # Nume diferit
        self.confirm_pass_input = QLineEdit()  # Nume diferit
        self.confirm_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.confirm_pass_label)
        layout.addWidget(self.confirm_pass_input)

        self.message_label = QLabel("")
        self.message_label.setStyleSheet("color: #FF5555;")
        layout.addWidget(self.message_label)
        layout.addStretch()

        button_layout = QHBoxLayout()
        self.save_button = QPushButton("Save Changes")
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setStyleSheet("background-color: #4A4A4A;")

        button_layout.addStretch()
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.save_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

        self.save_button.clicked.connect(self.on_save_clicked)
        self.cancel_button.clicked.connect(self.reject)  # self.reject închide

    def update_password_strength(self, password):
        score = 0
        if (len(password) > 0): score = score + 1
        if (len(password) >= 8): score = score + 1
        if re.search(r"[a-zA-Z]", password) and re.search(r"\d", password): score = score + 1
        if re.search(r"[!@#$%^&*(),.?:{}|<>_]", password): score = score + 1

        self.strength_bar.setValue(score)

        if score == 1:
            color = "#CC0000"
        elif score == 2:
            color = "#FF8C00"
        elif score == 3:
            color = "#E0E000"
        elif score == 4:
            color = "#00A859"
        else:
            color = "transparent"
        self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: %s; border-radius: 5px; }" % color)

    def on_save_clicked(self):
        current_pass = self.current_pass_input.text()
        new_pass = self.new_pass_input.text()
        confirm_pass = self.confirm_pass_input.text()

        self.message_label.setText("")
        if not current_pass or not new_pass or not confirm_pass:
            self.message_label.setText("Please fill all fields")
            return
        if new_pass != confirm_pass:
            self.message_label.setText("Passwords don't match")
            return
        if self.strength_bar.value() < 2:
            self.message_label.setText("Password is too weak")
            return

        try:
            user_data = get_login_data(self.username)
            if not user_data:
                self.message_label.setText("Error: User not found")
                return
            old_salt, old_encrypted_dek, _ , _= user_data
            old_kek = generate_key_from_password(current_pass.encode('utf-8'), old_salt)
            try:
                decrypt_data(old_kek, old_encrypted_dek)
            except InvalidTag:
                self.message_label.setText("Current password is incorrect")
                return

            new_salt = generate_salt()
            new_kek = generate_key_from_password(new_pass.encode('utf-8'), new_salt)
            new_encrypted_dek_blob = encrypt_data(new_kek, self.dek)

            success = update_user_credentials(self.username, new_salt, new_encrypted_dek_blob)

            if success:
                self.accept()  # Închide dialogul cu succes
            else:
                self.message_label.setText("Failed to update database.")

        except Exception as e:
            self.message_label.setText(f"An error occurred: {e}")
            print(f"Error changing password: {e}")

class SettingsDialog(QDialog):
    """ Fereastra principală de Setări. """
    # Semnal emis când o pagină copil (ex. ChangePassword) se închide
    child_page_closed = pyqtSignal()

    def __init__(self, username, dek, parent=None):
        super().__init__(parent)
        self.username = username
        self.dek = dek  # Păstrăm DEK-ul pentru a-l pasa paginii de schimbare a parolei
        self.parent_app = parent  # Păstrăm referința la AppContainer

        self.setWindowTitle("Settings")
        self.setMinimumWidth(450)
        self.setStyleSheet(parent.styleSheet())

        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # --- Opțiunea 1: Schimbare Parolă ---
        pass_layout = QHBoxLayout()
        pass_label = QLabel("Security")
        pass_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #00A859;")
        pass_layout.addWidget(pass_label)
        pass_layout.addStretch()

        self.change_pass_button = QPushButton("Change Password...")
        self.change_pass_button.setFixedWidth(180)  # Mărime fixă
        pass_layout.addWidget(self.change_pass_button)
        layout.addLayout(pass_layout)

        # Linie separatoare
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("border-top: 1px solid #4A4A4A;")
        layout.addWidget(line)

        # --- Opțiunea 2: 2FA ---
        tfa_layout = QHBoxLayout()
        tfa_label_layout = QVBoxLayout()
        tfa_label = QLabel("Two-Factor Authentication")
        tfa_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #00A859;")
        tfa_desc = QLabel("Use an authenticator app for extra security.")
        tfa_desc.setStyleSheet("color: #AAAAAA;")  # Gri
        tfa_label_layout.addWidget(tfa_label)
        tfa_label_layout.addWidget(tfa_desc)

        tfa_layout.addLayout(tfa_label_layout)
        tfa_layout.addStretch()

        self.tfa_toggle = ToggleSwitch(self)  # Butonul glisant
        tfa_layout.addWidget(self.tfa_toggle)
        layout.addLayout(tfa_layout)

        layout.addStretch()

        # --- Buton Închidere ---
        button_layout = QHBoxLayout()
        self.close_button = QPushButton("Close")
        self.close_button.setStyleSheet("background-color: #4A4A4A;")

        button_layout.addStretch()
        button_layout.addWidget(self.close_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        # Conexiuni
        self.close_button.clicked.connect(self.reject)
        self.change_pass_button.clicked.connect(self.open_change_password)

        # --- CORECTURA FINALĂ: Ordinea corectă a logicii 2FA ---

        # 1. Setăm starea inițială FĂRĂ a declanșa semnalul
        current_secret = get_totp_secret(self.username)
        self.tfa_toggle.setChecked(current_secret is not None)

        # 2. Conectăm semnalul ACUM, pentru clicuri viitoare
        self.tfa_toggle.stateChanged.connect(self.on_tfa_toggled)

    def open_change_password(self):
        """ Deschide dialogul de schimbare a parolei (corectat). """
        dialog = ChangePasswordDialog(self.username, self.dek, self)

        # Executăm dialogul (fără self.hide/self.show)
        result = dialog.exec_()

        # Afișăm confirmarea DUPĂ ce dialogul s-a închis
        if result == QDialog.Accepted:
            QMessageBox.information(self, "Success", "Password updated successfully!")

    def on_tfa_toggled(self, state):
        """ Corectat pentru a preveni crash-ul 0xC0000409. """
        if state == Qt.Checked:
            QTimer.singleShot(0, self.open_enable_2fa_dialog)
        else:
            QTimer.singleShot(0, self.open_disable_2fa_dialog)

    def open_enable_2fa_dialog(self):
        """ Funcție ajutătoare apelată de QTimer pentru a deschide dialogul 2FA în siguranță. """
        try:
            dialog = Enable2FADialog(self.username, self)
            if dialog.exec_() == QDialog.Accepted:
                print("2FA Enabled")
            else:
                # Utilizatorul a anulat sau a eșuat
                print("2FA enabling cancelled or failed.")

                # Blocăm semnalele pentru a preveni bucla
                self.tfa_toggle.blockSignals(True)
                self.tfa_toggle.setChecked(False)  # Comută butonul înapoi pe OFF
                self.tfa_toggle.blockSignals(False)  # Reactivăm semnalele
        except Exception as e:
            print(f"EROARE la deschiderea Enable2FADialog: {e}")
            QMessageBox.critical(self, "Eroare Dependințe",
                                 f"Nu s-a putut deschide dialogul 2FA:\n{e}\n\nVerifică dacă 'pyotp' și 'qrcode' sunt instalate.")
            self.tfa_toggle.blockSignals(True)
            self.tfa_toggle.setChecked(False)  # Și comutăm înapoi pe OFF
            self.tfa_toggle.blockSignals(False)


    def open_disable_2fa_dialog(self):
        """ Funcție ajutătoare apelată de QTimer pentru a dezactiva 2FA în siguranță. """
        reply = QMessageBox.question(self, "Disable 2FA",
                                     "Are you sure you want to disable Two-Factor Authentication?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            set_totp_secret(self.username, None)  # Șterge cheia din DB
            QMessageBox.information(self, "Success", "2FA has been disabled.")
        else:
            self.tfa_toggle.blockSignals(True)
            self.tfa_toggle.setChecked(True)  # Comută butonul înapoi pe ON
            self.tfa_toggle.blockSignals(False)
class Enable2FADialog(QDialog):
    def __init__(self,username,parent=None):
        super().__init__(parent)
        self.username=username
        self.setStyleSheet(parent.styleSheet())
        self.setWindowTitle("Enable 2FA")
        self.setMinimumWidth(400)

        layout=QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20,20,20,20)
        self.secret_key = pyotp.random_base32()
        uri = pyotp.totp.TOTP(self.secret_key).provisioning_uri(
            name=self.username,
            issuer_name="Cryptic Safe"
        )
        qr_image=qrcode.make(uri)

        buffer = io.BytesIO()
        qr_image.save(buffer, "PNG")
        qr_pixmap = QPixmap()
        qr_pixmap.loadFromData(buffer.getvalue(), "PNG")

        qr_label = QLabel()
        qr_label.setPixmap(qr_pixmap.scaled(250, 250, Qt.KeepAspectRatio))
        qr_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(qr_label)
        info_label = QLabel("Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.).")
        info_label.setWordWrap(True)
        info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_label)
        verify_label = QLabel("Enter the 6-digit code to verify:")
        self.code_input = QLineEdit()
        self.code_input.setAlignment(Qt.AlignCenter)
        self.code_input.setMaxLength(6)

        layout.addWidget(verify_label)
        layout.addWidget(self.code_input)

        self.message_label = QLabel("")
        self.message_label.setStyleSheet("color: #FF5555;")  # Roșu
        layout.addWidget(self.message_label)

        # 6. Butoane
        button_layout = QHBoxLayout()
        self.verify_button = QPushButton("Verify & Enable")
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setStyleSheet("background-color: #4A4A4A;")

        button_layout.addStretch()
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.verify_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.verify_button.clicked.connect(self.on_verify)
        self.cancel_button.clicked.connect(self.reject)  # Închide dialogul

    def on_verify(self):
        code = self.code_input.text()
        if not code.isdigit() or len(code) != 6:
            self.message_label.setText("Please enter a valid 6-digit code.")
            return

        # Verifică dacă codul este corect
        totp = pyotp.TOTP(self.secret_key)
        if totp.verify(code):
            # Codul e corect! Salvăm cheia în baza de date
            success = set_totp_secret(self.username, self.secret_key)
            if success:
                QMessageBox.information(self, "Success", "2FA has been enabled successfully!")
                self.accept()  # Închide cu succes
            else:
                # --- AICI ESTE MODIFICAREA ---
                # Am schimbat QLabel cu un QMessageBox
                QMessageBox.critical(self, "Eroare Bază de Date",
                                     "Eroare: Nu s-a putut salva secretul 2FA în baza de date.")
                # self.message_label.setText("Failed to save 2FA secret to database.")
        else:
            self.message_label.setText("Invalid code. Please try again.")

if __name__ == '__main__':
    app = QApplication(sys.argv)

    # --- Încărcare Font Awesome (AICI E CORECTURA) ---
    fontDB = QFontDatabase()

    # Construiește o cale absolută către font, pornind de la locația scriptului
    try:
        script_dir = Path(__file__).parent
    except NameError:
        script_dir = Path.cwd()  # Fallback dacă rulezi într-un mod ciudat (ex: REPL)

    font_path = script_dir / "Font Awesome 7 Free-Solid-900.otf"

    # Verifică dacă fișierul chiar există înainte de a-l încărca
    if not font_path.exists():
        print(f"EROARE: Fișierul font NU A FOST GĂSIT la: {font_path}")
    else:
        # Folosim str(font_path) pentru a da calea ca string
        font_id = fontDB.addApplicationFont(str(font_path))

        if font_id == -1:
            print(f"EROARE: Nu am putut încărca fontul: {font_path}")
        else:
            families = fontDB.applicationFontFamilies(font_id)
            if families:
                FA_FONT_NAME = families[0]
                print(f"Font Awesome încărcat cu succes: '{FA_FONT_NAME}'")
            else:
                print(f"EROARE: Fontul {font_path} este invalid.")
    # ----------------------------------------------------

    setup_users_database()

    try:
        BASE_VAULT_PATH.mkdir(parents=True, exist_ok=True)

        if not BASE_VAULT_PATH.exists():
            raise Exception("Vault folder not created! Verifică permisiunile sau rulează cu drepturi de admin.")

        print("[OK] Folder creat/verificat:", BASE_VAULT_PATH)

        # setează atribute (Windows). Ignorăm return dacă nu e Windows.
        try:
            if os.name == 'nt':
                res = ctypes.windll.kernel32.SetFileAttributesW(str(BASE_VAULT_PATH), 0x02 | 0x04)
                if res == 0:
                    print("[WARN] Unable to set folder attributes (maybe not running as admin).")
        except Exception as e:
            print("[WARN] SetFileAttributes failed:", e)

    except Exception as e:
        print(f"[EROARE] {e}")
        sys.exit(1)

    container = AppContainer()
    container.show()

    sys.exit(app.exec())
