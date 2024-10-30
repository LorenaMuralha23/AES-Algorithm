package com.mycompany.aes.algorithm;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author USER
 */
public class AESEncryption {

    private final String encryptAlgorithm = "AES/CBC/PKCS5Padding";

    public String readFile(File fileToRead) {
        BufferedReader bufferReader = null;
        String completeMessage = "";
        try {
            bufferReader = new BufferedReader(new FileReader(fileToRead));
            StringBuilder srBuilder = new StringBuilder();
            String lineReadText;
            while ((lineReadText = bufferReader.readLine()) != null) {
                srBuilder.append(lineReadText);
                srBuilder.append("\n");
            }
            completeMessage = srBuilder.toString();

        } catch (FileNotFoundException ex) {
            Logger.getLogger(AESEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AESEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                bufferReader.close();
            } catch (IOException ex) {
                Logger.getLogger(AESEncryption.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return completeMessage;
    }

    /**
     * The generateKeyFromPassword method details (pt-br): SecureRandom: é usado
     * para criar um gerador de números aleatórios que é seguro para uso em
     * criptografia. Ele produz números aleatórios de alta qualidade
     * nextBytes(): gera bytes aleatórios e os coloca no array salt.
     * getInstance(): retorna uma instância de uma fábrica de chaves que pode
     * ser usada para gerar chaves a partir de dados específicos, como uma
     * senha. Neste caso, a fábrica de chaves usa o algoritmo
     * PBKDF2WithHmacSHA256 (Password-Based Key Derivation Function 2, com HMAC
     * SHA-256). KeySped: uma interface em Java que define uma especificação de
     * chave, ou seja, ela contém as informações necessárias para gerar ou
     * derivar uma chave criptográfica. PBEKeySpec: O método PBEKeySpec cria um
     * especificador de chave baseado em senha (Password-Based Encryption Key
     * Specification). generateSecret(): é chamado na SecretKeyFactory para
     * realmente gerar a chave. Ele pega o especificador de chave (PBEKeySpec)
     * que você criou, que contém a senha, o sal, o número de iterações e o
     * tamanho da chave, e usa esses dados para criar uma chave criptográfica.
     * getEncoded(): converte a chave secreta gerada em uma forma de byte array
     * (byte[]). SecretKeySpec: serve para informar que o array de bytes gerado
     * é uma chave para o algoritmo AES, especificando que o algoritmo
     * criptográfico associado a essa chave será o AES (Advanced Encryption
     * Standard)
     *
     * @param password
     * @return SecrectKey
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public SecretKey generateKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }

    /**
     * The generateIV method details (pt-br): IvParameterSpec: classe que
     * armazena o vetor de inicialização (IV) necessário para modos de
     * criptografia como o AES em CBC ou CTR
     *
     * @return IvParameterSpec
     */
    public IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public void encrypt(File contentToEncrypt, SecretKey secretKey, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        String messageToEncrypt = readFile(contentToEncrypt);
        Cipher cipher = Cipher.getInstance(this.encryptAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] cipherText = cipher.doFinal(messageToEncrypt.getBytes());
        System.out.println("Message encrypted successfully!");
        saveFile("encryptedMessages", "encryptedMessage.txt", Base64.getEncoder().encodeToString(cipherText));
    }

    public void decrypt(File contentToDecrypt, SecretKey secretKey, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        String encryptedMessage = readFile(contentToDecrypt);

        encryptedMessage = encryptedMessage.replaceAll("\\s+", ""); // Remove todos os espaços em branco e quebras de linha

        byte[] cipherText = Base64.getDecoder().decode(encryptedMessage);

        Cipher cipher = Cipher.getInstance(this.encryptAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] plainText = cipher.doFinal(cipherText);

        System.out.println("Message decrypted successfully!");
        saveFile("decryptedMessages", "decryptedMessage.txt", new String(plainText));
    }

    public void saveFile(String folderName, String encryptedFileName, String encryptedMessage) {
        FileWriter fileWriter = null;
        String currentDir = System.getProperty("user.dir");
        try {
            String encryptedMsgPath = currentDir + "\\" + folderName + "\\"
                    + encryptedFileName;
            fileWriter = new FileWriter(encryptedMsgPath);
            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
            bufferedWriter.write(encryptedMessage);

            System.out.println("File saved successfully!\n");

            //closing resources
            bufferedWriter.close();
        } catch (IOException ex) {
            Logger.getLogger(AESEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fileWriter.close();
            } catch (IOException ex) {
                Logger.getLogger(AESEncryption.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
}
