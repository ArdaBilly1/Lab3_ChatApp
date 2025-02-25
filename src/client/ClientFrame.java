/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package client;

import java.rmi.RemoteException;
import java.util.Calendar;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author MohammadA
 */
public class ClientFrame extends javax.swing.JFrame {

    Client client;
    int lastMsgRecived;
    /**
     * Creates new form clientFrame
     */
    public ClientFrame(Client client) {
        this.client=client;
        initComponents();
        refresh.start();
    }

       Thread refresh = new Thread(new Runnable() {

            @Override
            public void run() {
                try {
                    lastMsgRecived = client.getNumMessages();
                } catch (RemoteException ex) {
                    Logger.getLogger(ClientFrame.class.getName()).log(Level.SEVERE, null, ex);
                }
                while(true) {
                    try {
                        Thread.sleep(100);
                        get_new_messages();
                    } catch (InterruptedException e) {
                        
                    } catch (RemoteException ex) {
                        Logger.getLogger(ClientFrame.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (Exception ex) {
                        Logger.getLogger(ClientFrame.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
        });
       
    public void get_new_messages() throws RemoteException, Exception {
        
        int numMsgToRecive = client.getNumMessages() - lastMsgRecived;
        System.out.println(client.getNumMessages() + " " + lastMsgRecived);
        System.out.println(numMsgToRecive);
       
        if(numMsgToRecive == 1)
        {
            displayMsg(client.getNewMessage(lastMsgRecived+1));
            lastMsgRecived++;
        }
        if(numMsgToRecive > 1)
        {
            System.out.println("gnm");
            for(int i = lastMsgRecived + 1; i<client.getNumMessages(); i++)
            {
                displayMsg(client.getNewMessage(i));
            }
        }  
    }   
    
    public void displayMsg(String message) throws Exception
    {
//        client.displayMessage(message);
        chatBox.append(message+"\n on decrypted= "+client.displayMessage(message)+ "\n");
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        chatBox = new javax.swing.JTextArea();
        msgText = new javax.swing.JTextField();
        msgSend = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Client");

        chatBox.setEditable(false);
        chatBox.setColumns(20);
        chatBox.setLineWrap(true);
        chatBox.setRows(5);
        jScrollPane1.setViewportView(chatBox);

        msgSend.setText("Send");
        msgSend.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                msgSendActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 356, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(msgText)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(msgSend)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 329, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(msgText, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(msgSend))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void msgSendActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_msgSendActionPerformed
        
        try {
            client.sendMessage(msgText.getText());
        } catch (RemoteException ex) {
            Logger.getLogger(ClientFrame.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(ClientFrame.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_msgSendActionPerformed



    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea chatBox;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton msgSend;
    private javax.swing.JTextField msgText;
    // End of variables declaration//GEN-END:variables
}
