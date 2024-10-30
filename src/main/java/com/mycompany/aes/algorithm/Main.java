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
import javax.swing.JFileChooser;

public class Main {

    public static void main(String[] args) {
        try {
            Scanner input = new Scanner(System.in);
            AESEncryption cryptography = new AESEncryption();
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

            System.out.println("Type a password: ");
            String password = input.nextLine();

            //Gerando a key
            SecretKey key = cryptography.generateKeyFromPassword(password);
            //Gerando o vetor de inicialização
            IvParameterSpec iv = cryptography.generateIV();

            cryptography.encrypt(fileToEncrypt, key, iv);

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    

}
