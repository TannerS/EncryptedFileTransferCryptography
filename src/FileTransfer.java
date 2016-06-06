import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
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

//*************************************************************EXCEPTION CATCHING FOR THROW NEW ETC

//****************************************************CLIENT IS IN A LOOP TO DO MANY THINGS

/*

 - server should then calculatoe when it hist last chunk and sends  ack to cient
-- sever then creates file 



*/

public class FileTransfer 
{
    // needed static variables
    static final String OPTION_1 = "makekeys";
    static final String OPTION_2 = "server";
    static final String OPTION_3 = "client";
    static final int INITIAL_ACK = 0;
    static final int ERR_ACK = -1;
    static final String OUTPUT_FILE_NAME = "data.txt";
        
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
        //SecretKey skey = null;
        Key skey = null;
        int expected_seq = 0;
        byte[] data = null;
        byte[] rec_file = null;
        int rec_counter = 0;
        int file_size = 0;
        float num_of_chunks = 0;
        Message message = null;
        String filename = null;
        File file = null;
        ServerSocket serverSocket = null;
        int remainder = 0;
        int total_chunks = 0;
        int chunksize = 0;
        /*
        try 
        {
            // start server on port number
            serverSocket = new ServerSocket(Integer.parseInt(port));
        }
        catch (IOException ex) 
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("start server socket reates");
*/
        
        
        
        
        
        
        // set loop to  true
        outter_loop = true;
        // this loop controlls when a user wishes too be able to accept another client
        while(outter_loop)
        {
            System.out.println("Start server inner loop");
            
            
            
            try 
            {

            // start server on port number
            serverSocket = new ServerSocket(Integer.parseInt(port));

            System.out.println("start server socket reates");
                
                
                // wait for client to connect
                socket = serverSocket.accept();
                // init input/output streams
                in_object_stream = new ObjectInputStream(socket.getInputStream());
                out_object_stream = new ObjectOutputStream(socket.getOutputStream());
            } 
            catch (IOException ex) 
            {
                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            // set loop bool back to true for this user
            inner_loop = true;
            // reset counter
            rec_counter = 0;
            // this loop controls the objects froming from client  

            System.out.println("server streams opened");

            while(inner_loop)
            {
                System.out.println("Server inner loop");
                try 
                {
                    // server will read in object of Message
                    message = (Message) in_object_stream.readObject();
                    
                    
                    
                    
                } 
                catch (IOException | ClassNotFoundException ex) 
                {
                    Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                }
                System.out.println("server get message");

                // usermessage object to determine type
                switch(message.getType()) 
                {
                    // if message is a disconnect message
                    case DISCONNECT:
                        System.out.println("server discoect message");
              
                        try 
                        {
                            //*************************************************************8does break break switch or loop?
                            // close server
                            serverSocket.close();
                            socket.close();
                            // close streams
                            in_object_stream.close();
                            out_object_stream.close();
                            //throw new ClientDisconnectedException("DISCONNECT MESSAGE FROM SERVERS");
                            inner_loop = false;
                            break;
                        } 
                        catch (IOException | ClientDisconnectedException ex) 
                        {
                            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        finally
                        {
                            inner_loop = false;
                            
                        }
                    break;    
                    // if message is a disconnect message
                    case START:

                        System.out.println("server start message ");

                        // cast object to StartMessage
                        start_message = (StartMessage) message;
                        // checks for validity 
                        // if any of these conditions are true
                        // something is not right
                        if(start_message.getChunkSize() == 0 || start_message.getEncryptedKey().length == 0 || start_message.getFile() == null)
                        {
                            System.out.println("server bad message");
                            try 
                            {
                                // send to client a -1 ack meaning error
                                out_object_stream.writeObject(new AckMessage(ERR_ACK));
                            } 
                            catch (IOException ex) 
                            {
                                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                            }
                            throw new InvalidMessage("ERROR WITH START MESSAGE");
                        }
                        System.out.println("server message is good");
                        // create file object of private key
                        file = new File(pr_filename);
                        // check if file exist
                        if(!file.exists())
                            // throw exception
                            throw new FileNotFoundException("PRIVATE KEY NOT FOUND");
                        try 
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
                            skey = cipher.unwrap(start_message.getEncryptedKey(), "AES", Cipher.SECRET_KEY);
                            
                            
                            System.out.println("KEY FORMAT ALG : "+ skey.getAlgorithm());
                            System.out.println("KEY FORMAT ALG : "+ skey.getFormat());
                            
                                                       System.out.print("KEY FORMAT BYTEs : " +  Arrays.toString(skey.getEncoded()));

                            System.out.println("got key");
                            // assuming everything is proper, send ack back to client
                            out_object_stream.writeObject(new AckMessage(INITIAL_ACK));
                        } 
                        catch (IOException | InvalidKeyException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException ex) 
                        {
                            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        // save file size
                        file_size = (int)start_message.getSize();
                        // set filename
                        filename = start_message.getFile();
                        // create btye array of size of file
                        rec_file = new byte[file_size];
                        
                        System.out.println("DEBUG FILE SIZE: " + file_size);
                        System.out.println("DEBUG ARR SIZE: " + rec_file.length);
                        
                        // record chunk size
                        chunksize = start_message.getChunkSize();
                        // set seq value (needs to be reste for each client)
                        expected_seq = 0;
                        System.out.println("server end start message switch");
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
                        break;
                    }
                    case CHUNK:
                        System.out.println("server got chunk  message");
                        // ************************************************************the data adds to file byets each chunk, how do we know when file is finoshed?, stop message? rec_counter == size of file? what!
                        // convert message to proper object
                        chunk = (Chunk) message;
                        //**************************************************************************************test missing seq thing
                        // decrypt the data from the chunk
                        //************************************************************make sure skey is not null
                        data = decryptData("AES", skey, chunk.getData());
                        
    
                        
                        
                        // calculat crc32 value
                        int crc = generateCRC32(data);
                        // check if chunk is the proper expected seq or crc
                        if((chunk.getSeq() != expected_seq) || (crc != chunk.getCrc()))
                        {
                            // either seq is incorrect or crc is
                            try 
                            {
                                // in both cases, we need to resubmit last seq
                                out_object_stream.writeObject(new AckMessage(expected_seq));  
                            } 
                            catch (IOException ex) 
                            {
                                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                        else
                        {
                            
                             System.out.println("server file size: " + rec_file.length+ " chunk size: " + data.length);
                            // using the counter and size of file from the startmessage step, add the data
                           // for(int i = 0; i < chunk.getData().length; i++)
                                                   System.out.println("CHUNK");
                           for(int i =0 ; i < data.length; i++)
                               System.out.printf("%02X", data[i]);
                           
                           
                        //byte[] chunk_data = chunk.getData();
                           
                           for(int i = 0; i < data.length; i++)
                            {
                                // ***********************************************************************this syntax works?
                                //System.out.println("REC COUNTER: " + rec_counter + " i: " + i);
                               // rec_file[rec_counter++] = chunk.getData()[i];*************************************************
                                rec_file[rec_counter++] = data[i];
                                //rec_counter++;
                                
                            }
                           
                           System.out.println("\nRECCOUNTER: " + (rec_counter) + " REC SIDE: " + rec_file.length + " FILE SIZE: " + file.length() );
                            
                            // increment for the next sequence number
                            expected_seq++;

                            try 
                            {
                                // send ack with the next seq
                                out_object_stream.writeObject(new AckMessage(expected_seq));
                            } 
                            catch (IOException ex)
                            {
                                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                            }
                            
                            // *********************************************************check for last chunk
                            // ************************************************************is last ack fro mserver to client or client to server? may need to change this line backward to do so
                                         
                            remainder = (int) (file_size % chunksize);
                            total_chunks = (file_size / chunksize);
                            total_chunks += (remainder >= 1) ? 1 : 0;
                            
                            System.out.println("\nSEQ: "+ expected_seq + " TOTAL: " + total_chunks);

                            
                            // no more chunks to recieve 
                            if(expected_seq == total_chunks)
                            {
                                System.out.println("LAST CHUNK");

                                 try {
                                     out_object_stream.writeObject(new AckMessage(expected_seq));
                                 } catch (IOException ex) {
                                     Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                                 }
                                 
                                 
                                                         System.out.println("FILE");
                           for(int i =0 ; i < rec_file.length; i++)
                               System.out.printf("%02X", rec_file[i]);
                                 
                                // create file from bytes
                                writeBytesToFile(filename, rec_file);
                                // server will leave the while loop and go to outter loop for new ocnection
                                inner_loop = false;
                                
                                 //System.out.println("FILE: " + Arrays.toString(rec_file));
                            }
                            
                            // ***********************************************************************************************check file size aginats seq number (number of chunk) and if last chunk client should get ack n in which client will send disconnect message, but sever createst he file based off methids below 
                            System.out.println("Chunks completed [" + expected_seq + "/" + "]");
                            
         
                        }
                    break;
                }
            }
        }
    }
    
    public static void clientMode(String pu_filename, String host, String port)
    {
        //***************************************************************************need to be able to have more then oen client after one finishes
        // declare needed objects
        ObjectInputStream in_object = null;
        ObjectOutputStream out_object = null;
        byte[] enkey = null;
        Scanner scanner = new Scanner(System.in);
        //Path filepath = null;
        String location = null;
        int chunksize = 1024;
        StartMessage start_message = null;
        Socket socket = null;
        Message message = null;
        AckMessage ack = null;
        byte[] bfile = null;
        File file = null;
        Key skey = null;
        int seq = -1;
        Chunk chunk = null;
        // previous chunk*******************************************************************************
        Chunk prev_chunk = null;
        
        try 
        {
            // create socket with port number  
            socket = new Socket(host, Integer.parseInt(port));
            // create streams
            out_object = new ObjectOutputStream(socket.getOutputStream());
            in_object = new ObjectInputStream(socket.getInputStream());
            // check if key exist
            file = new File(pu_filename);
            if (!file.exists())
                throw new FileNotFoundException(file.getAbsolutePath());
            // generate session key
            skey = generateAESKey("AES", 256);
            
            
                               System.out.println("KEY FORMAT ALG : "+ skey.getAlgorithm());
                            System.out.println("KEY FORMAT ALG : "+ skey.getFormat());
                             System.out.print("KEY FORMAT BYTEs : " +  Arrays.toString(skey.getEncoded()));
                            Arrays.toString(skey.getEncoded());
            
            // wrap session key with server's public key
            enkey = wrapSecretKey(pu_filename, "RSA", skey); 
            // ask user for path of file to send over to server
            System.out.println("Please enter file name: ");
            // get path as string
           // location = scanner.nextLine();
           location = "test.txt";
            // set string of path to file object, this is to check if it exist
            file = new File(location);
            // check if location exist
            if(!file.exists())
                // throw exception
                throw new FileNotFoundException(file.getAbsolutePath());
            // use string object to create byte array of that file
            bfile = Files.readAllBytes(Paths.get(location));
            
            
             System.out.println("FILE SIZE: " + file.length()+ " ARRY SIZE " + bfile.length  );
            
            //System.out.println("FILE: " + Arrays.toString(bfile));
            
            
                           System.out.println("FILE");
                           for(int i =0 ; i < bfile.length; i++)
                               System.out.printf("%02X", bfile[i]);
            
            // ask user the chunk size for the file transfer
            System.out.println("\nPlease enter desired file chunk size in bytes: ");
            // read in size
           // chunksize = scanner.nextInt();
           chunksize = 1024;
            // if size is less than 0
            if(chunksize < 1)
                // throw exception
                throw new InvalidSizeException("Chunk size to small");
            // send start message to server 
            out_object.writeObject(new StartMessage(location, enkey, chunksize));
            // the reply back from server (should have init seq of 0)
            ack = (AckMessage) in_object.readObject();
            // if seq num = -1 means stop transfer
            if(ack.getSeq() == -1)
            {
                // close resources 
                socket.close();
                out_object.close();
                in_object.close();
                return;
            }
            // message is a ack of 0, meaning to start the transfer 
            else if(ack.getSeq() == 0)
            {
                System.out.println("client ack = 0");
                // record seq number
                seq = ack.getSeq();
                // create temp array to hold the chunk size
                byte[] temp = new byte[chunksize];//*********************************************
              // byte[] temp = null;// = new byte[chunksize];
               byte[] temp2 = null;
                // counter used to keep track of the chunk elements
                int counter = 0;
                System.out.println("client before only loop");
                // calculate remainder
                int remainder = (int) (bfile.length % chunksize);
                
                System.out.println("R***************************************************** : " + remainder);
                // get total chunks
                int total_chunks = (bfile.length / chunksize);
                total_chunks += (remainder >= 1) ? 1 : 0;
                // loop the size of the file
                for(int i = 0; i < bfile.length; i++)
                {
                    System.out.printf("DATA: %02X: at i: %d and counter: %d \n",  bfile[i], i, counter );
                    // the current byte is size of the chunk
                    // i = 1
                    if((i % chunksize == 0) && i != 0)
                    //if(i % chunksize == 0 && i != 0)
                    {
                       // System.out.println("***DEBUG: " + temp.length + " COUNTER: " + counter + " bfile: "+ bfile.length+ " i: " + i);
                       //temp[counter++] = bfile[i];
                       
                        System.out.println("creating chunks");
                        //********************************************************************************************temp solution to un even chunk sizes

                        // temp[counter] = bfile[i];
                         System.out.println("EVEN ARRAY");
                        // System.out.println("CHUNK: " + Arrays.toString(temp));
                        System.out.println("chunk");
                        for(int j =0 ; j < temp.length; j++)
                            System.out.printf("%02X", temp[j]);
                         chunk = createChunk(temp, seq, skey);    
                           out_object.writeObject(chunk);
                        System.out.println("sent chunk");
                        // read in next message
                        //message = (Message) in_object.readObject();
                        System.out.println("client got message back");
                        // check message type
                        ack = (AckMessage) in_object.readObject();
    
                        // if this was las t chunk
                        if(ack.getSeq() == total_chunks )
                        {
                            //out_object
                            // break
                            break;
                        }
                        
                        // check for error
                        if(ack.getSeq() == -1)
                        {
                            // close resources 
                            socket.close();
                            out_object.close();
                            in_object.close();
                            throw new ErrorSequenceNumberException("-1 Seq");
                        } 
                        // that ack was the last one
                        // file transfer is done
                        else if(ack.getSeq() == total_chunks)
                        {
                            // send disconnect message to client
                            out_object.writeObject(new DisconnectMessage());
                            break;
                        }
                        // not done sending chunks
                        //else
                        //{
                            // increase the next seq number
                            ++seq;
                            // reset counter
                            counter = 0;
                            
                            //temp[counter++] = bfile[i];
                        //}
                        
                        
                    }
                    // not a perfect chunk
                   // else
                   // {
                        // keep adding data
                        temp[counter++] = bfile[i];//************************************************************fix error if null, inf loop on server exceptio
                   // counter++;
                    //}
                }
                    
                    
                    
                    
                    
                     // System.out.println("***DEBUG: " + temp.length + " COUNTER: " + counter + " bfile: "+ bfile.length+ " i: " + i);
                     //  temp[counter] = bfile[i];
                        
                        
                        System.out.println("creating chunks");
                        //********************************************************************************************temp solution to un even chunk sizes

                        
                        
                         temp2 = new byte[counter];
                            System.arraycopy(temp, 0, temp2, 0, temp2.length);
                                    System.out.println("chunk");
                           for(int j =0 ; j < temp2.length; j++)
                               System.out.printf("%02X", temp2[j]);
                            chunk = createChunk(temp2, seq, skey); 
                           out_object.writeObject(chunk);
                        System.out.println("sent chunk");
                        // read in next message
                        //message = (Message) in_object.readObject();
                        System.out.println("client got message back");
                        // check message type
                        ack = (AckMessage) in_object.readObject();
    
      
                        // check for error
                        if(ack.getSeq() == -1)
                        {
                            // close resources 
                            socket.close();
                            out_object.close();
                            in_object.close();
                            throw new ErrorSequenceNumberException("-1 Seq");
                        } 
                        // that ack was the last one
                        // file transfer is done
                        else if(ack.getSeq() == total_chunks)
                        {
                            // send disconnect message to client
                            out_object.writeObject(new DisconnectMessage());
                           
                        }
                    
                   
                
                /********************************************************************************************************************************
                /*
                    After sending all chunks and receiving the final ACK, the transfer has completed and the client can
                    either begin a new file transfer or disconnect.
               */
                
              // out_object.writeObject(new DisconnectMessage());
                
              
            }
        } 
        catch (IOException | ClassNotFoundException ex) 
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
    
    static void writeBytesToFile(String filename, byte[] data) throws FileNotFoundException
    {
        System.out.println("\nFILE 1");
        
        try 
        {
            Files.write(new File(filename).toPath(), data);
        } 
        catch (IOException ex) 
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        System.out.println("FILE 2");
        try 
        {

            FileOutputStream fs = new FileOutputStream(new File("test2.txt"));
            BufferedOutputStream bs = new BufferedOutputStream(fs);
            bs.write(data);
            bs.close();
        } 
        catch (Exception ex) 
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        System.out.println("FILE 3");
        
         FileOutputStream fos;
        //below is the different part
        File someFile = new File("test3.txt");
        
        try {
            someFile.createNewFile();
            fos = new FileOutputStream(someFile);
            fos.write(data);
            fos.flush();
            fos.close();
            
        } catch (IOException ex) {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        
       
        /*
        try {
          //  
            
            //  int bytes;
            // fos.write(bytes);
            //fos.flush();
            //fos.close();
            
            
        
        } catch (FileNotFoundException ex) {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        */
        
    }
    
    static Chunk createChunk(byte[] temp, int seq, Key skey)
    {
        
        System.out.println("\nclienthit chunk size");
        int crc32 = generateCRC32(temp);
        System.out.println("client crc calculated");
        temp = encryptData("AES", skey, temp);
        //Chunk chunk = new Chunk(seq, temp, crc32);
        System.out.println("encryped data and chunck created: seq: " + seq);
        return new Chunk(seq, temp, crc32);
    }
    
    static AckMessage sendReceiveChunk(Chunk chunk, ObjectInputStream in_object, ObjectOutputStream out_object)
    {
        AckMessage ack = null;
        
        try 
        {
            // send chunk
            out_object.writeObject(chunk);
            System.out.println("sent chunk");
            // read in next message
            //message = (Message) in_object.readObject();
            System.out.println("client got message back");
            // check message type
            //System.out.println("Chunks completed [" + ((AckMessage)message).getSeq() + "/" + num_of_chunks + "]");
            //System.out.println("END TRNSFER: SEQ: " + ack.getSeq()  +"NUM OF CHUNKS: " + num_of_chunks);
            ack = (AckMessage) in_object.readObject();
        } 
        catch (IOException | ClassNotFoundException ex) 
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        return ack;
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
    
    public static class InvalidSizeException extends RuntimeException //Exception
    {   
        public InvalidSizeException(String message)
        {
            super(message);
        }

        public InvalidSizeException(Throwable cause)
        {
           super(cause);
        }
    }
    
    public static class ClientDisconnectedException extends RuntimeException //Exception
    {   
        public ClientDisconnectedException(String message)
        {
            super(message);
        }

        public ClientDisconnectedException(Throwable cause)
        {
           super(cause);
        }
    }
    
    public static class InvalidMessage extends RuntimeException //Exception
    {   
        public InvalidMessage(String message)
        {
            super(message);
        }

        public InvalidMessage(Throwable cause)
        {
           super(cause);
        }
    }
    
        public static class ErrorSequenceNumberException extends RuntimeException //Exception
    {   
        public ErrorSequenceNumberException(String message)
        {
            super(message);
        }

        public ErrorSequenceNumberException(Throwable cause)
        {
           super(cause);
        }
    }
        
    public static class FileNotFoundException extends RuntimeException //Exception
    {   
        public FileNotFoundException(String message)
        {
            super(message);
        }

        public FileNotFoundException(Throwable cause)
        {
           super(cause);
        }
    }
}


