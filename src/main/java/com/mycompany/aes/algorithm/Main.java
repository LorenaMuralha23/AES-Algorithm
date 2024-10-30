package com.mycompany.aes.algorithm;

import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.InputMap;
import javax.swing.JFileChooser;

public class Main {

    public static AESEncryption cryptography = new AESEncryption();
    public static Scanner input = new Scanner(System.in);

    public static void main(String[] args) {
        IvParameterSpec iv = null;
        SecretKey key = null;
        int option = 0;

        while (option != 3) {
            System.out.println("====== AES Algorithm Menu ======");
            System.out.println("Choose an option");
            System.out.println("1 - Encrypt file");
            System.out.println("2 - Decrypt file");
            System.out.println("3 - exit");
            option = Integer.parseInt(input.nextLine());

            if (option != 3) {
                try {
                    File fileToProcess = openFileChooser();

                    switch (option) {
                        case 1:

                            System.out.println("Type a password: ");
                            String password = input.nextLine();
                            System.out.println("");

                            if (key == null || iv == null) {
                                //Gerando a key
                                key = cryptography.generateKeyFromPassword(password);
                                //Gerando o vetor de inicialização
                                iv = cryptography.generateIV();
                            }
                            cryptography.encrypt(fileToProcess, key, iv);
                            break;

                        case 2:
                            if (key != null && iv != null) {
                                cryptography.decrypt(fileToProcess, key, iv);
                            } else {
                                System.out.println("You have to define the initialization vector and the key to decrypt the message!");
                            }
                            break;
                        default:
                            throw new AssertionError();
                    }
                } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }

    }

    public static File openFileChooser() {
        File fileToEncrypt = null;

        JFileChooser fileChooser = new JFileChooser();

        fileChooser.setDialogTitle("Choose a file to encrypt");

        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

        int result = fileChooser.showOpenDialog(null);

        if (result == JFileChooser.APPROVE_OPTION) {
            fileToEncrypt = fileChooser.getSelectedFile();

        } else {
            System.out.println("No file was chosen.");
        }

        return fileToEncrypt;
    }

}
