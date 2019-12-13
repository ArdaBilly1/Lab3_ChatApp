package client;

import server.*;
import java.rmi.*;
import java.util.Base64;
import java.util.Calendar;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class Client {

    ChatServerInterface server;
    String username;
    ConnectFrame connectframe;
    ClientFrame clientframe;
    int lastMsgRecived;
    static Cipher cipher;
    String encryptedText;
    SecretKey secretKey;

    public void init(){
        connectframe=new ConnectFrame(this);
        connectframe.setVisible(true);
        
    }

    public void connect(String username, String ip_address, Calendar date) {
        try {
            server = (ChatServerInterface) Naming.lookup("rmi://" + ip_address + "/chatService");
            lastMsgRecived = server.get_num_messages(); //Marker for when user entered conversation
                                                        //User will not recive messages prior to when they joined
            this.username = username;
            this.connectframe.setVisible(false);
            clientframe=new ClientFrame(this);
            this.clientframe.setVisible(true);
            server.newConnection(username);
        } catch (Exception e) {
            System.out.println(e);
        }
    }
    
    public void sendMessage(String message) throws RemoteException
            ,Exception
    {
        
        java.util.Date date = new java.util.Date();
        String outgoing;
        String enkrip;
        
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        secretKey = keyGenerator.generateKey();
        cipher = Cipher.getInstance("AES");
        
        encryptedText = encrypt(message, secretKey);
        
        outgoing = date.toString() + " ["+username+"]: " + encryptedText;
        
        server.incoming_message(outgoing);
    }
    public String displayMessage(String message) throws Exception{
        
        String decrypted = decrypt(encryptedText, secretKey);
        message = decrypted;
        return message;
    }
    
    private static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
       Base64.Decoder decoder = Base64.getDecoder();
       byte[] encryptedTextByte = decoder.decode(encryptedText);
       cipher.init(Cipher.DECRYPT_MODE, secretKey);
       byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
       String decryptedText = new String(decryptedByte);
       return decryptedText;
    }
    private static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        byte[] plainTextByte = plainText.getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedByte = cipher.doFinal(plainTextByte);
        Base64.Encoder encoder = Base64.getEncoder();
        String encryptedText = encoder.encodeToString(encryptedByte);
        return encryptedText;
    }

    public int getNumMessages() throws RemoteException{
        return server.get_num_messages();
    } 
    
    public String getNewMessage(int messageNum) throws RemoteException
    {
        return server.get_new_message(messageNum);
    }
    
    public static void main(String args[]) {
        try {
            Client client=new Client();
            client.init();  
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
