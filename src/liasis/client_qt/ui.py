# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'liasis_client_qt_main.ui'
#
# Created: Fri Aug 10 00:17:15 2007
#      by: PyQt4 UI code generator 4.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

class Ui_main_window(object):
    def setupUi(self, main_window):
        main_window.setObjectName("main_window")
        main_window.resize(QtCore.QSize(QtCore.QRect(0,0,965,389).size()).expandedTo(main_window.minimumSizeHint()))

        self.centralwidget = QtGui.QWidget(main_window)
        self.centralwidget.setObjectName("centralwidget")

        self.gridlayout = QtGui.QGridLayout(self.centralwidget)
        self.gridlayout.setObjectName("gridlayout")

        self.torrent_list = QtGui.QTreeView(self.centralwidget)

        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Ignored,QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.torrent_list.sizePolicy().hasHeightForWidth())
        self.torrent_list.setSizePolicy(sizePolicy)
        self.torrent_list.setSizeIncrement(QtCore.QSize(1,1))

        font = QtGui.QFont()
        font.setFamily("Sans Serif")
        font.setPointSize(8)
        self.torrent_list.setFont(font)
        self.torrent_list.setObjectName("torrent_list")
        self.gridlayout.addWidget(self.torrent_list,0,0,1,1)
        main_window.setCentralWidget(self.centralwidget)

        self.menubar = QtGui.QMenuBar(main_window)
        self.menubar.setGeometry(QtCore.QRect(0,0,965,29))
        self.menubar.setObjectName("menubar")
        main_window.setMenuBar(self.menubar)

        self.statusbar = QtGui.QStatusBar(main_window)
        self.statusbar.setObjectName("statusbar")
        main_window.setStatusBar(self.statusbar)

        self.retranslateUi(main_window)
        QtCore.QMetaObject.connectSlotsByName(main_window)

    def retranslateUi(self, main_window):
        main_window.setWindowTitle(QtGui.QApplication.translate("main_window", "Liasis", None, QtGui.QApplication.UnicodeUTF8))

