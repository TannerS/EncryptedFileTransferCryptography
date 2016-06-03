import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.CRC32;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

//************************************************************CLOSE FILES AND OBJECT STREAMS

public class FileTransfer 
{
    // needed static variables
    static final String OPTION_1 = "makekeys";
    static final String OPTION_2 = "server";
    static final String OPTION_3 = "client";
    static final int INITIAL_ACK = 0;
    static final int ERR_ACK = -1;
        
    public static void main(String[] args) 
    {
        // check if user typed in arguments
        if(args.length > 0)
        {
            // the first argument determines the mode
            switch (args[0].toLowerCase().trim()) 
            {
                // user wants to generate keys
                case OPTION_1:
                    // generate RSA key pair into directory
                    generateRSAKeys();
                    break;
                // user wants to run in server mode
                case OPTION_2:
                    // check for other required arguments
                    // args[1] = filename of private key
                    // args[2] = port number
                    if(args.length == 3)
                        // run server
                        serverMode(args[1], args[2]);
                    // user is missing required
                    else
                        // throw exception
                        throw new IllegalArgumentException();
                    break;
                // user wants to run in client mode
                case OPTION_3:
                    // check for other required arguments
                    // args[1] = filename of public key
                    // args[2] = host
                    // args[3] = port number
                    if(args.length == 4)
                        // run client 
                        clientMode(args[1], args[2], args[3]);
                    // user is missing required
                    else
                        // throw exception
                        throw new IllegalArgumentException();
                    break;
                // user entered unknown argument
                default:
                    // throw exception
                    throw new IllegalArgumentException();
            }
        }
        else
            throw new IllegalArgumentException();
    }
    
    public static void generateRSAKeys()
    {
        // needed objects
        KeyPairGenerator generator = null;
        KeyPair kpair = null;
                
        try 
        {
            // prepare generator for RSA key pair
            generator = KeyPairGenerator.getInstance("RSA");
            // initialize bit size
            generator.initialize(1024); 
            // generate key pair
            kpair = generator.genKeyPair();
            // create public key file on computer
            try (ObjectOutputStream out_object = new ObjectOutputStream(new FileOutputStream(new File("public.bin")))) 
            {
                // get public key from keypair object and write it to file
                out_object.writeObject(kpair.getPublic());
            }
            // create public key file on computer
            try (ObjectOutputStream out_object = new ObjectOutputStream(new FileOutputStream(new File("private.bin")))) 
            {
                // get private key from keypair object and write it to file
                out_object.writeObject(kpair.getPrivate());
            }
        } 
        // exception if error occurs 
        catch (NoSuchAlgorithmException | IOException e) 
        {
            e.printStackTrace(System.err);
        }
    }
    
    public static void serverMode(String pr_filename, String port) //throws IOException
    {
        // declare needed objects
        ObjectOutputStream out_object_stream = null;
        ObjectInputStream in_object_stream = null;
        boolean outter_loop = true;
        boolean inner_loop = true;
        Socket socket = null;
        ObjectInputStream in_object = null;
        PrivateKey prkey = null;
        Cipher cipher = null;
        StartMessage start_message = null;
        Key unwrapped_key = null;
        // start server on port number
        try (ServerSocket serverSocket = new ServerSocket(Integer.parseInt(port))) 
        {  
            // this loop controlls when a user wishes too be able to accept another client
            while(outter_loop)
            {
                // wait for client to connect
                socket = serverSocket.accept();
                // set loop bool back to true for this user
                inner_loop = true;
                // init input/output streams
                in_object_stream = new ObjectInputStream(socket.getInputStream());
                out_object_stream = new ObjectOutputStream(socket.getOutputStream());
                // this loop controls the objects froming from client
                while(inner_loop)
                {
                    // server will read in object of Message
                    Message message = (Message) in_object_stream.readObject();
                    // usermessage object to determine type
                    switch(message.getType()) 
                    {
                        // if message is a disconnect message
                        case DISCONNECT:
                            // disconnect inner loop
                            inner_loop = false;
                            // close server
                            socket.close();
                            // close streams
                            in_object_stream.close();
                            out_object_stream.close();
                            break;
                        // if message is a disconnect message
                        case START:
                            // cast object to StartMessage
                            start_message = (StartMessage) message;
                            // checks for validity 
                            // if any of these conditions are true
                            // something is not right
                            if( start_message.getChunkSize() == 0 || 
                                start_message.getEncryptedKey().length == 0 || 
                                start_message.getFile() == null )
                            {
                                // send to client a -1 ack meaning error
                                out_object_stream.writeObject(new AckMessage(ERR_ACK));
                            }
                            // everything with the message is ok
                            else
                            {
                                // read in the private key
                                in_object = new ObjectInputStream(new FileInputStream(new File(pr_filename)));
                                // transfer object (as stream) into proper object
                                prkey = (PrivateKey) in_object.readObject();
                                // set cipher for RSA
                                cipher = Cipher.getInstance("RSA");
                                // unwrap (decrypt) private key setup
                                cipher.init(Cipher.UNWRAP_MODE, prkey);
                                // unwrap encrypted key to get unencrypted AES key
                                unwrapped_key = cipher.unwrap(start_message.getEncryptedKey(), "RSA", Cipher.PRIVATE_KEY);
                                // assuming everything is proper, send ack back to client
                                out_object_stream.writeObject(new AckMessage(INITIAL_ACK));
                            }
                            break;     
                        case STOP:
                            break;
                        case CHUNK:
                            break;
                        // unknown object sent
                        default:
                            // throw exception
                            throw new UnsupportedOperationException();
                    }
                }
            }
        }
        catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) 
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        } 
    }
    
    public static void clientMode(String pu_filename, String host, String port)
    {
        // declare needed objects
        ObjectInputStream in_object = null;
        ObjectOutputStream out_object = null;
        InputStream in = null;
        OutputStream out = null;
        PrivateKey prkey = null;
        PublicKey pukey = null;
        Cipher cipher = null;
        KeyGenerator keygen = null;
        byte[] enkey = null;
        Scanner scanner = new Scanner(System.in);
        //Path filepath = null;
        String location = null;
        int chunksize = 1024;
        StartMessage start_message;
        Socket socket = null;
        Message message = null;
        AckMessage ack = null;
        byte[] bfile = null;
        File file = null;
        SecretKey skey = null;
        File filelocation = null;
        int seq = -1;
        
        try 
        {
            // read in public key file
            in_object = new ObjectInputStream(new FileInputStream(new File(pu_filename)));
            // create object based off public key stream
            pukey = (PublicKey) in_object.readObject();
            // generator created for AES
            keygen = KeyGenerator.getInstance("AES");
            // set key size in bits
            keygen.init(256);
            // generate AES session key
            skey = keygen.generateKey();
            // set cipher for AES
            cipher = Cipher.getInstance("RSA");
            // set cipher to wrap public key
            cipher.init(Cipher.WRAP_MODE, pukey);
            // wrap the aes session key (encrypt the aes key using rsa public key)
            cipher.wrap(skey);
            // get the encrypted aes key
            enkey = cipher.doFinal();                  
            // ask user for path of file tosend over to server
            System.out.println("Please enter path of file: ");
            // get path as string
            location = scanner.nextLine();
            // set string of path to file object, this is to check if it exist
            filelocation = new File(location);
            // check if location exist
            // if it does not
            if(!filelocation.exists())
                // throw exception
                throw new FileNotFoundException(filelocation.getAbsolutePath());
            // use string object to create byte array of that file
            bfile = Files.readAllBytes(Paths.get(location));
            // ask user the chunk size for the file transfer
            System.out.println("Please enter desired file chunk size in bytes: ");
            // read in size
            chunksize = scanner.nextInt();
            // if size is less than 0
            if(chunksize < 1)
                // throw exception
                throw new UnsupportedOperationException();
            // create a new start message
            start_message = new StartMessage(location, enkey, chunksize);
            // create socket with port number  
            socket = new Socket(host, Integer.parseInt(port));
            // create streams
            out_object = new ObjectOutputStream(socket.getOutputStream());
            in_object = new ObjectInputStream(socket.getInputStream());
            // send start message to server 
            out_object.writeObject(start_message);
            // the reply back from server
            message = (Message) in_object.readObject();
        }
        // catches anyone of these exceptions
        catch (NoSuchAlgorithmException | InvalidKeyException | IOException | ClassNotFoundException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidPathException ex)
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        try
        {
            // check the server's reply for message type
            switch(message.getType()) 
            {
                // the message is a ACK
                case ACK:
                    // message is a ack of 0, meaning to start the transfer 
                    if(ack.getSeq() == 0)
                    {
                        // record seq number
                        seq = ack.getSeq();
                        
                        try
                        {
                            // get streams from socket
                            in_object = new ObjectInputStream(socket.getInputStream());
                            out_object = new ObjectOutputStream(socket.getOutputStream());

                        } 
                        catch (IOException ex) 
                        {
                            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        
                        
                        
                        // create temp array to hold the chunk size
                        byte[] temp = new byte[chunksize];
                        // used to hold the crc32 value
                        int crc32 = 0;
                        // chunk object to send to server
                        Chunk chunk = null;
                        // counter used to keep track of the chunk elements
                        int counter = 0;
                        // loop the size of the file
                        for(int i = 0; i < bfile.length; i++)
                        {
                            // the current byte is size of the chunk
                            if(i % chunksize == 0 && i != 0)
                            {
                                // since i will stop at the chunk size
                                // we can't forget that current byte
                                temp[counter++] = bfile[i];
                                // get crc32
                                crc32 = generateCRC32(temp);
                                // set cipher to deal with aes
                                cipher = Cipher.getInstance("AES");
                                // set cipher for wrapping mode using the AESkey
                                cipher.init(Cipher.WRAP_MODE, skey);
                                // encrypt this data into new byte array
                                temp = cipher.doFinal(temp);
                                //init chunk object
                                chunk = new Chunk(++seq, temp, crc32);
                                // send chunk
                                out_object.writeObject(chunk);
                                // read in next message
                                message = (Message) in_object.readObject();
                                // check message type
                                switch(message.getType()) 
                                {
                                    // the message is a ACK
                                    case ACK:
                                        System.out.println("Chunk number: " + ((AckMessage)message).getSeq());
                                        break;
                                    // anything else is incorrect
                                    default:
                                       throw new UnsupportedOperationException();
                                }   
                            }
                            else
                                temp[counter++] = bfile[i];
                        }
                    }
                    else if(ack.getSeq() == -1)
                    {
                        throw new IllegalArgumentException();
                    }
                    break;
                // any other type of message is unexpected 
                default:
                    throw new UnsupportedOperationException();
            }
        }
        catch (InvalidPathException | IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex)
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    static int generateCRC32(byte[] bytes)
    {
        // create object
        CRC32 check_sum = new CRC32();
        // generat crc32 based off bytes
        check_sum.update(bytes);
        // retun value of the crc32
        return (int) check_sum.getValue();
    }
}


