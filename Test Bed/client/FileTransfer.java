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
        Chunk chunk = null;
        SecretKey skey = null;
        int expected_seq = 0;
        byte[] data = null;
        byte[] rec_file = null;
        int rec_counter = 0;
        int file_size = 0;
        float num_of_chunks = 0;
        
        System.out.println("Start server");
        
        // start server on port number
        try (ServerSocket serverSocket = new ServerSocket(Integer.parseInt(port))) 
        {  
            
            System.out.println("start server socket reates");
            
            // set loop to  true
            outter_loop = true;
            // this loop controlls when a user wishes too be able to accept another client
            while(outter_loop)
            {
                System.out.println("Start server inner loop");
                
                
                // wait for client to connect
                socket = serverSocket.accept();
                // set loop bool back to true for this user
                inner_loop = true;
                // init input/output streams
                in_object_stream = new ObjectInputStream(socket.getInputStream());
                out_object_stream = new ObjectOutputStream(socket.getOutputStream());
                // reset counter
                rec_counter = 0;
                // this loop controls the objects froming from client  
                
                System.out.println("server streams opened");
                
                while(inner_loop)
                {
                    System.out.println("Server inner loop");
                    
                    
                    // server will read in object of Message
                    Message message = (Message) in_object_stream.readObject();
                    
                    System.out.println("server get message");
                    
                    // usermessage object to determine type
                    switch(message.getType()) 
                    {
                        // if message is a disconnect message
                        case DISCONNECT:
                            
                            System.out.println("server discoect message");
                            
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
                            
                            System.out.println("server start message ");
                            
                            // cast object to StartMessage
                            start_message = (StartMessage) message;
                            // checks for validity 
                            // if any of these conditions are true
                            // something is not right
                            if( start_message.getChunkSize() == 0 || 
                                start_message.getEncryptedKey().length == 0 || 
                                start_message.getFile() == null )
                            {
                                
                                System.out.println("server bad message");
                                // send to client a -1 ack meaning error
                                out_object_stream.writeObject(new AckMessage(ERR_ACK));
                                inner_loop = false;
                            }
                            // everything with the message is ok
                            else
                            {
                                System.out.println("server message is good");
                                // read in the private key
                                in_object = new ObjectInputStream(new FileInputStream(new File(pr_filename)));
                                // transfer object (as stream) into proper object
                                prkey = (PrivateKey) in_object.readObject();
                                // set cipher for RSA
                                cipher = Cipher.getInstance("RSA");
                                // unwrap (decrypt) private key setup
                                cipher.init(Cipher.UNWRAP_MODE, prkey);
                                // unwrap encrypted key to get unencrypted AES key
                                skey = (SecretKey) cipher.unwrap(start_message.getEncryptedKey(), "AES", Cipher.SECRET_KEY);
                                
                                System.out.println("got key");
                                
                                
                                // assuming everything is proper, send ack back to client
                                
                                out_object_stream.writeObject(new AckMessage(INITIAL_ACK));
                                
                                System.out.println("server sent first ack");
                                
                                // save file size
                                file_size = (int)start_message.getSize();
                                // create btye array of size of file
                                rec_file = new byte[file_size];
                                //  calculate number of chunks
                                num_of_chunks = (start_message.getSize() / start_message.getChunkSize());
                                
                                System.out.println("server end start message switch");
                            }
                            break;     
                        case STOP:
                        {
                            System.out.println("server stop message");
                            
                            try 
                            {
                                // send -1 ack
                                out_object_stream.writeObject(new AckMessage(ERR_ACK));
                            } 
                            catch (IOException ex) 
                            {
                                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                            }
                            // set bools to false to end loops
                            inner_loop = false;
                            //outter_loop = false;
                            break;
                        }
                        case CHUNK:
                            System.out.println("server got chunk  message");
                            
                            // ***********************************************************need ot check for star message first??, chunk cant happen withotu start mesage
                            // ************************************************************the data adds to file byets each chunk, how do we know when file is finoshed?, stop message? rec_counter == size of file? what!
                            // convert message to proper object
                            chunk = (Chunk) message;
                            // check if chunk is the proper expected seq
                            if(chunk.getSeq() == expected_seq)
                            {
                                // decrypt the data from the chunk
                                //************************************************************make sure skey is not null
                                data = decryptData("AES", skey, chunk.getData());
                                // calculat crc32 value
                                int crc = generateCRC32(data);
                                // if crc values do not match
                                if(crc != chunk.getCrc())
                                {
                                    // send ack with the same seq
                                    out_object_stream.writeObject(new AckMessage(expected_seq));
                                }
                                // the crc values match
                                else
                                {
                                    // using the counter and size of file from the startmessage step, add the data
                                    for(int i = 0; i < chunk.getData().length; i++)
                                        // ***********************************************************************this syntax works?
                                        rec_file[rec_counter++] = chunk.getData()[i];
                                    // increment for the next sequence number
                                    expected_seq++;
                                    // increase chunk count
                                   // num_of_chunks++;

                                    try 
                                    {
                                        // send ack with the next seq
                                        out_object_stream.writeObject(new AckMessage(expected_seq));
                                    } 
                                    catch (IOException ex)
                                    {
                                        Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                                    }
                                    
                                    // display to screen
                                    // **********************************************************************************check if size ocunt is correct
                                    System.out.println("Chunks completed [" + expected_seq + "/" + num_of_chunks);
              
                                    // check for final chunk
                                    // match seq num to chunk size
                                    if((expected_seq - 1) == num_of_chunks)
                                    {
                                        // the last chunk, was the last chunk needed
                                        // break loop
                                        //(***************************************************************************put together final result using file name
                                        break;
                                    }
                                } 
                            }
                            else
                            {
                               // send ack with the seq that was not ack
                               out_object_stream.writeObject(new AckMessage(expected_seq));
                            }
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
        //***************************************************************************need to be able to have more then oen client after one finishes
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
        //SecretKey skey = null;
        Key skey = null;
        File filelocation = null;
        int seq = -1;
        float num_of_chunks = 0;
        
        try 
        {
            System.out.println("client start");
            
            // check if key exist
            file = new File(pu_filename);
            if (!file.exists())
            {
                throw new FileNotFoundException(file.getAbsolutePath());
                //return;
            }
            // generate session key
            skey = generateAESKey("AES", 256);
            // wrap session key with server's public key
            enkey = wrapSecretKey(pu_filename, "RSA", skey); 
            
             //********************************************************************check if key file exist
            // ask user for path of file tosend over to server
            System.out.println("Please enter file name: ");
            // get path as string
           //                            location = scanner.nextLine();
           location = "test.txt";
            // set string of path to file object, this is to check if it exist
            filelocation = new File(location);
            // check if location exist
            // if it does not
            if(!filelocation.exists())
                // throw exception
                throw new FileNotFoundException(filelocation.getAbsolutePath());
            
            System.out.println("client file exist");
            
            // use string object to create byte array of that file
            bfile = Files.readAllBytes(Paths.get(location));
            
                        System.out.println("client read in file as bytes");
            
            // ask user the chunk size for the file transfer
            System.out.println("Please enter desired file chunk size in bytes: ");
            // read in size
           // chunksize = scanner.nextInt();
           chunksize = 1024;
            // if size is less than 0
            if(chunksize < 1)
                // throw exception
                throw new UnsupportedOperationException();
            // set the number of chunks
            num_of_chunks = (filelocation.length() / chunksize);
            System.out.println("client FILE SIZE: " + filelocation.length());
            System.out.println("client CHUNK SIZE: " + (filelocation.length() / chunksize));
                        System.out.println("client before start");
            
            // create a new start message
            start_message = new StartMessage(location, enkey, chunksize);
            
                        System.out.println("client after start");
            
            // create socket with port number  
            socket = new Socket(host, Integer.parseInt(port));
            
                        System.out.println("client cfreated  socket");
            
            // create streams
            out_object = new ObjectOutputStream(socket.getOutputStream());
            in_object = new ObjectInputStream(socket.getInputStream());
            
            
                        System.out.println("client before sending start");
            // send start message to server 
            out_object.writeObject(start_message);
            
            
            System.out.println("client after  sending start");
            
            
            // the reply back from server (should have init seq of 0)
            message = (Message) in_object.readObject();
            
            System.out.println("client got mesage back from server");
        }
        // catches anyone of these exceptions
        catch (IOException | ClassNotFoundException | InvalidPathException ex)
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        try
        {
            
            System.out.println("client check mesage type");
            
            // check the server's reply for message type
            // the init message
            switch(message.getType()) 
            {
                // the message is a ACK
                case ACK:
                    System.out.println("client ack message ");
                    
                    ack = (AckMessage) message;
                    
                    
                    // message is a ack of 0, meaning to start the transfer 
                    if(ack.getSeq() == 0)
                    {
                        System.out.println("client ack = 0");
                        
                        // record seq number
                        seq = ack.getSeq();
                        // create temp array to hold the chunk size
                        byte[] temp = new byte[chunksize];
                        // used to hold the crc32 value
                        int crc32 = 0;
                        // chunk object to send to server
                        Chunk chunk = null;
                        // previous chunk*******************************************************************************
                        Chunk prev_chunk = null;
                        // counter used to keep track of the chunk elements
                        int counter = 0;
                        
                        
                        System.out.println("client before only loop");
                        
                        
                        //calculate remainder
                        int r = (int) (filelocation.length() % chunksize);
                        // use totla to get position when remaidner is hit
                        long pos =  filelocation.length();
                        
                        int i = 0;
                        
                        // loop the size of the file
                        for(i = 0; i < bfile.length; i++)
                        {
                            
                             System.out.println("i: " + i + " count: " + counter);
                            
                            // the current byte is size of the chunk
                           // if((i % chunksize == 0 && i != 0) || (counter == (r-2) && i == (bfile.length - 1)))
                            if(i % chunksize == 0 && i != 0)
                            {
                                System.out.println("clienthit chunk size");
                                // get crc32
                                crc32 = generateCRC32(temp);                         
                                System.out.println("client crc calculated");
                                // encrypt data
                                temp = encryptData("AES", skey, temp);
                                //init chunk object (seq is the next wanted ack)
                                chunk = new Chunk(++seq, temp, crc32);
                                System.out.println("encryped data and chunck created: seq: " + seq);
                                /// do final for encrypt / decrypt, wrap for keys, and use a preve chunk to keep track of hcunks*************
                                // send chunk
                                out_object.writeObject(chunk);
                                System.out.println("sent chunk");
                                // read in next message
                                message = (Message) in_object.readObject();
                                System.out.println("client got message back");
                                // check message type
                                System.out.println("Chunks completed [" + ((AckMessage)message).getSeq() + "/" + num_of_chunks + "]");
                                // reset counter for next chunk
                                counter = 0;
                                System.out.println("END TRNSFER: SEQ: " + ack.getSeq()  +"NUM OF CHUNKS: " + num_of_chunks);
                                //if(((AckMessage)message).getSeq() == (int)num_of_chunks)
                                   // System.out.println("LAST CHUNK:");
                            }
                            // not a perfect chunk
                            else
                                // keep adding data
                                temp[counter++] = bfile[i];
                        }
                        // if the file is not a perfect chunk, mean it has a remainder that is not the chunk size
                        // send last chunk with remainding data
                        //  temp[counter++] = bfile[i]; has been runnign but never hit the if statement
                        // if(i % chunksize == 0 && i != 0)
                        // so this wil lfill in the rest
                        // in the change the chunksize and file size is even divisiable, the last stat
                        // will be the if(i % chunksize == 0 && i != 0) before getting to this line
                        // however that is why we check if(counter != 0)
                        // since counter = 0 happens BEFORE leaving loop
                        // so this check shouls prevent it from happening
                        if(counter != 0)
                        {
                            System.out.println("clienthit chunk size");
                            // get crc32
                            crc32 = generateCRC32(temp);                         
                            System.out.println("client crc calculated");
                            // encrypt data
                            temp = encryptData("AES", skey, temp);
                            //init chunk object (seq is the next wanted ack)
                            chunk = new Chunk(++seq, temp, crc32);
                            System.out.println("encryped data and chunck created: seq: " + seq);
                            /// do final for encrypt / decrypt, wrap for keys, and use a preve chunk to keep track of hcunks*************
                            // send chunk
                            out_object.writeObject(chunk);
                            System.out.println("sent chunk");
                            // read in next message
                            message = (Message) in_object.readObject();
                            System.out.println("client got message back");
                            // check message type
                            System.out.println("Chunks completed [" + ((AckMessage)message).getSeq() + "/" + num_of_chunks + "]");
                            // reset counter for next chunk
                            counter = 0;
                            System.out.println("END TRNSFER: SEQ: " + ack.getSeq()  +"NUM OF CHUNKS: " + num_of_chunks);  
                        }
                        
                        
                
            
                        
                        
                    }
                    else if(ack.getSeq() == -1)
                    {
                        // close resources 
                        socket.close();
                        out_object.close();
                        in_object.close();
                        throw new IllegalArgumentException();
                    }
                    break;
                // any other type of message is unexpected 
                default:
                    throw new UnsupportedOperationException();
            }
        }
        catch (InvalidPathException | IOException | ClassNotFoundException ex)
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
    
    static Key generateAESKey(String type, int bitsize)
    {
       // Cipher cipher = null;
       // SecretKey skey = null;
        KeyGenerator keygen = null;
        
        try {
            // generator created for AES
            keygen = KeyGenerator.getInstance(type.toUpperCase().trim());
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        // set key size in bits
        //keygen.init(bitsize);
        // generate AES session key and return it
        return keygen.generateKey();
    }
    
    static byte[] wrapSecretKey(String path, String type, Key skey )
    {
        ObjectInputStream in_object = null;
        PublicKey pukey = null;
        Cipher cipher = null;
        byte[] temp = null;
        
        try 
        {
            // read in public key file
            in_object = new ObjectInputStream(new FileInputStream(new File(path)));
            // create object based off public key stream
            pukey = (PublicKey) in_object.readObject();
            // set cipher for AES
            cipher = Cipher.getInstance(type.toUpperCase().trim());
            // set cipher to wrap public key
            cipher.init(Cipher.WRAP_MODE, pukey);
            // wrap the aes session key (encrypt the aes key using rsa public key
            temp = cipher.wrap(skey);
        } 
        catch (NoSuchAlgorithmException | NoSuchPaddingException | ClassNotFoundException | InvalidKeyException | IOException | IllegalBlockSizeException ex) 
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        // return the encrypted key
        return temp;     
    }
    //  temp = encryptData("AES", skey, temp);
    static byte[] encryptData(String instance, Key key, byte[] data)
    {
        Cipher cipher = null;
        byte[] temp = null;
        
        try 
        {
            // set cipher to deal with aes
            cipher = Cipher.getInstance(instance.toUpperCase().trim());
            // set cipher for wrapping mode using the AESkey
            cipher.init(Cipher.ENCRYPT_MODE, key);
            // encrypt this data into new byte array
            temp = cipher.doFinal(data);
        } 
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) 
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        finally
        {
            return temp;
        }
    }
    
    static byte[] decryptData(String instance, Key key, byte[] data)
    {
        Cipher cipher = null;
        byte[] temp = null;
        
        try 
        {
            // set cipher to deal with aes
            cipher = Cipher.getInstance(instance.toUpperCase().trim());
            // set cipher for wrapping mode using the AESkey
            cipher.init(Cipher.DECRYPT_MODE, key);
            // encrypt this data into new byte array
            temp = cipher.doFinal(data);
        } 
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) 
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        finally
        {
            return temp;
        }
    }

}


