package com.kostenko.rsa;

import com.kostenko.rsa.core.RSA;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by Alexander on 06.04.2015.
 */
public class MainWindow extends JFrame {

    private JPanel jPanelMain;
    private JTextArea textAreaOriginalText;
    private JButton buttonEncrypt;
    private JTextArea textAreaOpenKeyPair;
    private JTextArea textAreaPrivateKeyPair;
    private JTextArea textAreaCipherText;
    private JTextArea textAreaDecryptedText;
    private JLabel labelText;
    private JLabel labelOpenKeyPair;
    private JLabel labelPrivateKeyPair;
    private JLabel labelCipherText;
    private JLabel labelDecryptedText;
    private JTextField textFieldKeySize;
    private JLabel labelKeySize;
    private JButton buttonDecrypt;
    private RSA rsa;

    public MainWindow() {
        setContentPane(jPanelMain);
        setMinimumSize(jPanelMain.getMinimumSize());
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setVisible(true);
        buttonEncrypt.setEnabled(false);
        buttonDecrypt.setEnabled(false);
        setEventHandlers();
    }

    private void setEventHandlers() {
        textAreaOriginalText.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                super.keyReleased(e);
                checkDataForEncryption();
            }
        });
        textFieldKeySize.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                super.keyReleased(e);
                checkDataForEncryption();
            }
        });
        buttonEncrypt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                encryptData();
            }
        });
        buttonDecrypt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                decryptData();
            }
        });
    }


    private void checkDataForEncryption() {
        String originText = textAreaOriginalText.getText();
        String keySize = textFieldKeySize.getText();
        Pattern pattern = Pattern.compile("\\d*");
        Matcher matcher = pattern.matcher(keySize);
        int key = 0;
        if (keySize.length() > 0 && matcher.matches()) {
            try {
                key = Integer.parseInt(keySize);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage() + "Change key size between 4 and 10");
            }
        }
        if (originText.length() > 0 && key > 4 && key < 10)
            buttonEncrypt.setEnabled(true);
        else buttonEncrypt.setEnabled(false);
    }


    private void encryptData() {
        buttonDecrypt.setEnabled(true);
        String originText = textAreaOriginalText.getText();
        String keySize = textFieldKeySize.getText();
        int key = 0;
        if (keySize.length() > 0) {
            try {
                key = Integer.parseInt(keySize);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage() + "Change key size between 4 and 10");
            }
        }
        rsa = new RSA(key);
        rsa.encrypt(originText);
        String privateKey = rsa.getPrivatePair().getKey() + "";
        String privateN = rsa.getPrivatePair().getN() + "";
        String publicKey = rsa.getPublicPair().getKey() + "";
        String publicN = rsa.getPublicPair().getN() + "";
        String cipher = Arrays.toString(rsa.getCipherText());
        cipher = cipher.substring(cipher.indexOf("["), cipher.indexOf("]"));
        textAreaOpenKeyPair.setText("Key: " + publicKey + "\nN: " + publicN);
        textAreaPrivateKeyPair.setText("Key: " + privateKey + "\nN: " + privateN);
        textAreaCipherText.setText(cipher);
    }

    private void decryptData() {
        String result = rsa.decrypt(rsa.getCipherText(), rsa.getPrivatePair());
        textAreaDecryptedText.setText(result);
    }
}
