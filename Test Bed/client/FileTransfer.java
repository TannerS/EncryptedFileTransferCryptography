import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
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
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.CRC32;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

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
        // <editor-fold desc="Objects">
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
        Key skey = null;
        int expected_seq = 0;
        byte[] data = null;
        byte[] rec_file = null;
        int rec_counter = 0;
        int file_size = 0;
        Message message = null;
        String filename = null;
        File file = null;
        ServerSocket serverSocket = null;
        int remainder = 0;
        int total_chunks = 0;
        int chunksize = 0;
        // </editor-fold>
        // <editor-fold desc="Outter Loop">
        // set loop to  true
        outter_loop = true;
        // this loop controlls when a user wishes too be able to accept another client
        while(outter_loop)
        {
            System.out.println("Waiting For client to connect");
            try
            {
                // start server on port number
                serverSocket = new ServerSocket(Integer.parseInt(port));
                // wait for client to connect
                socket = serverSocket.accept();
                System.out.println("Client connected: " + socket.getInetAddress().toString().replace("/", ""));
                // init input/output streams
                in_object_stream = new ObjectInputStream(socket.getInputStream());
                out_object_stream = new ObjectOutputStream(socket.getOutputStream());
            }
            catch (IOException ex)
            {
                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
            }
            // reset counter
            rec_counter = 0;
            // <editor-fold desc="Inner Loop">
            // set loop bool back to true for this user
            inner_loop = true;
            // inner loop (each client does work in this)
            while(inner_loop)
            {
                try
                {
                    // server will read in object of Message
                    message = (Message) in_object_stream.readObject();
                }
                catch (IOException | ClassNotFoundException ex)
                {
                    Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                }
                // usermessage object to determine type
                switch(message.getType())
                {
                    // <editor-fold desc="Disconnect Message">
                    // if message is a disconnect message
                    case DISCONNECT:
                        inner_loop = false;
                        break;
                    // </editor-fold>
                    // <editor-fold desc="Start Message">
                    // if message is a start message
                    case START:
                        // cast object to StartMessage
                        start_message = (StartMessage) message;
                        // checks for validity
                        // if any of these conditions are true
                        // something is not right
                        if(start_message.getChunkSize() == 0 || start_message.getEncryptedKey().length == 0 || start_message.getFile() == null)
                        {
                            try
                            {
                                // send to client a -1 ack meaning error
                                out_object_stream.writeObject(new AckMessage(ERR_ACK));
                            }
                            catch (IOException ex)
                            {
                                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                            }
                            throw new InvalidMessageException("ERROR WITH START MESSAGE");
                        }
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
                        // record chunk size
                        chunksize = start_message.getChunkSize();
                        // math to calculate number of chunks
                        remainder = (int) (file_size % chunksize);
                        total_chunks = (file_size / chunksize);
                        total_chunks += (remainder >= 1) ? 1 : 0;
                        // set seq value (needs to be reste for each client)
                        expected_seq = 1;
                        break;
                    // </editor-fold>
                    // <editor-fold desc="Stop Message">
                    //if the message is a stop message
                    case STOP:
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
                        // create file from bytes
                        writeBytesToFile(filename, rec_file);
                        break;
                    // </editor-fold>
                    // <editor-fold desc="Chunk Message">
                    case CHUNK:
                        // convert message to proper object
                        chunk = (Chunk) message;
                        // decrypt the data from the chunk
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
                            System.out.println("Chunk received [" + chunk.getSeq() + "/"+ total_chunks + "]");
                            // using the counter and size of file from the startmessage step, add the data
                            for(int i = 0; i < data.length; i++)
                                rec_file[rec_counter++] = data[i];
                            try
                            {
                                // send ack with the next seq
                                out_object_stream.writeObject(new AckMessage(expected_seq));
                            }
                            catch (IOException ex)
                            {
                                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                            }
                            // no more chunks to recieve
                            if(expected_seq == total_chunks)
                            {
                                try
                                {
                                    out_object_stream.writeObject(new AckMessage(expected_seq));
                                }
                                catch (IOException ex)
                                {
                                    Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                                }
                            }
                            // increment for the next sequence number
                            expected_seq++;
                        }
                    break;
                    // </editor-fold>
                }
            }
            System.out.println("Transfer Complete");
            System.out.println("Output: " + filename);
            // <editor-fold desc="Closes">
            try
            {
               // unhook resources
               if(serverSocket != null)
                   serverSocket.close();
               if(socket != null)
                   socket.close();
               if(in_object_stream != null)
                   in_object_stream.close();
               if(out_object_stream != null)
                   out_object_stream.close();
               if(in_object != null)
                   in_object.close();
            }
            catch (IOException ex)
            {
                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
            }
            // </editor-fold>
        }
        // </editor-fold>
    }

    public static void clientMode(String pu_filename, String host, String port)
    {
        // <editor-fold desc="Objects">
        // declare needed objects
        ObjectInputStream in_object = null;
        ObjectOutputStream out_object = null;
        byte[] enkey = null;
        Scanner scanner = new Scanner(System.in);
        //Path filepath = null;
        String location = null;
        int chunksize = 1024;
        Socket socket = null;
        AckMessage ack = null;
        byte[] bfile = null;
        File file = null;
        Key skey = null;
        int seq = -1;
        Chunk chunk = null;
        boolean last_chunk;
        int total_chunks = 0;
        String answer = null;
        
        // </editor-fold>
        // <editor-fold desc="Open Socket/Streams">
        // loop so user can do the application multipel tines 
        do
        {
            try
            {
                // create socket with port number
                socket = new Socket(host, Integer.parseInt(port));
                System.out.println("Connected to server: " + socket.getInetAddress().toString());
                // create streams
                out_object = new ObjectOutputStream(socket.getOutputStream());
                in_object = new ObjectInputStream(socket.getInputStream());
            }
            catch (IOException ex)
            {
                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
            }
            // </editor-fold>
            // <editor-fold desc="Open File">

            // default value
            answer = "yes";
            last_chunk = false;
            
            try
            {
                // create file obeject from filename
                file = new File(pu_filename);
                // check if file exist
                if (!file.exists())
                    throw new FileNotFoundException(file.getAbsolutePath());
            }
            catch (FileNotFoundException ex)
            {
                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
            }
            // </editor-fold>
            // <editor-fold desc="Wrap Key">
            // generate session key
            skey = generateAESKey("AES", 256);
            // wrap session key with server's public key
            enkey = wrapSecretKey(pu_filename, "RSA", skey);
            // </editor-fold>
            // <editor-fold desc="Open and Read In File">
            // ask user for path of file to send over to server
            System.out.println("Please enter file name: ");
            // get path as string
            location = scanner.nextLine();
            // set string of path to file object, this is to check if it exist
            file = new File(location);
            try
            {
                // check if location exist
                if(!file.exists())
                    // throw exception
                    throw new FileNotFoundException(file.getAbsolutePath());
            }
            catch (FileNotFoundException ex)
            {
                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
            }
            try
            {
                // use string object to create byte array of that file
                bfile = Files.readAllBytes(Paths.get(location));
            }
            catch (IOException ex)
            {
                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
            }
            // </editor-fold>
            // <editor-fold desc="Chunk Size">
            // ask user the chunk size for the file transfer
            System.out.println("Please enter desired file chunk size in bytes: ");
            // read in size
            chunksize = scanner.nextInt();
            try
            {
                // if size is less than 0
                if(chunksize < 1)
                    // throw exception
                    throw new InvalidSizeException("Chunk size to small");
            }
            catch (InvalidSizeException ex)
            {
                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
            }
            // </editor-fold>
            System.out.println("Sending: " + location);
            System.out.println("File size (bytes): " + file.length());
            // <editor-fold desc="Ack">
            try
            {
                // send start message to server
                out_object.writeObject(new StartMessage(location, enkey, chunksize));
                // the reply back from server (should have init seq of 0)
                ack = (AckMessage) in_object.readObject();
            }
            catch (InvalidSizeException | IOException | ClassNotFoundException ex)
            {
                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
            }
            // </editor-fold>
            // <editor-fold desc="Invalid Ack (-1)">
            // if seq num = -1 means stop transfer
            if(ack.getSeq() == -1)
                // this will break it out of the loop where sockets close 
                break;
            // </editor-fold>
            // <editor-fold desc="Proper Ack (0)">
            // message is a ack of 0, meaning to start the transfer
            else if(ack.getSeq() == 0)
            {
                // record seq number
                seq = ack.getSeq();
                // create temp arrays to hold the chunk size
                byte[] temp = new byte[chunksize];
                byte[] temp2 = null;
                // counter used to keep track of the chunk elements
                int counter = 0;
                // calculate remainder
                int remainder = (int) (bfile.length % chunksize);
                // get total chunks
                total_chunks = (bfile.length / chunksize);
                total_chunks += (remainder >= 1) ? 1 : 0;
                System.out.println("Sending " + total_chunks + " chunks");
                // set bool to true;
                last_chunk = true;
                // loop the size of the file
                for(int i = 0; i < bfile.length; i++)
                {
                    // the current byte is size of the chunk
                    if(((i % chunksize == 0) && i != 0))
                    {
                        // create chunk
                        chunk = createChunk(temp, ++seq, skey);
                        try
                        {
                            // send chunk
                            out_object.writeObject(chunk);
                            System.out.println("Chunks completed [" + chunk.getSeq() + "/"+ total_chunks +"]");
                            // read in next message
                            ack = (AckMessage) in_object.readObject();
                        }
                        catch (IOException | ClassNotFoundException ex) 
                        {
                            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        // if this was last chunk
                        if(ack.getSeq() == total_chunks )
                        {
                            try
                            {
                                // send stop message to client
                                out_object.writeObject(new StopMessage(location));
                                // wait for reply
                                ack = (AckMessage) in_object.readObject();
                                // check seq number
                                if(ack.getSeq() == -1)
                                    break;
                            }
                            catch (IOException | ClassNotFoundException ex)
                            {
                                Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                            }
                            // if this was last chunk, set as false to not do work after loop
                            last_chunk = false;
                            // this will end current loop
                            break;
                        }
                        // check for error
                        else if(ack.getSeq() == -1)
                        {
                            // this will cause the work outside loop to not enter
                            last_chunk = false;
                            // this will now stop what is happening
                            break;
                        }
                        // reset counter
                        counter = 0;
                    }
                    // put file byte into temp array
                    temp[counter++] = bfile[i];
                }
                // if last chunk was not taken care of in loop
                // meaning last chunk was not evenly divisible 
                if(last_chunk)
                {
                    // temp array to hold a size other than chunk
                    temp2 = new byte[counter];
                    // copy elements over
                    System.arraycopy(temp, 0, temp2, 0, temp2.length);
                    try
                    {
                        // create chunk
                        chunk = createChunk(temp2, ++seq, skey);
                        // send chunk
                        out_object.writeObject(chunk);
                        System.out.println("Chunks completed [" + chunk.getSeq() + "/"+ total_chunks +"]");
                        // read in next message
                        ack = (AckMessage) in_object.readObject();    
                    }
                    catch (IOException | ClassNotFoundException ex)
                    {
                        Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
            // that ack was the last one
            // file transfer is done
            if(ack.getSeq() == total_chunks)
            {
                try
                {
                    // send stop message to client
                    out_object.writeObject(new StopMessage(location));
                    // wait for reply
                    ack = (AckMessage) in_object.readObject();
                }
                catch (IOException | ClassNotFoundException ex)
                {
                    Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
                }
            }          
            // ask user if they wish to send another file
            System.out.print("Transfer another file? (yes / no): ");
            // consume any left over null terminator form the nextInt earlier used
            scanner.nextLine();
            // get actually input
            answer = scanner.nextLine();
            System.out.println();
            //answer = answer.toLowerCase().trim();
        // loop if user chooses to transfer another
        }while(!answer.equals("no"));
        // no need to check for seq == -1 since after this, the statement will jump
        // out of the if statement back to the previous body which will do the socket closing
        // this is also where the sockets will be closed if the seq == -1 happens within the
        // earlier loop. the earlier loop is set that if seq == -1, to break from loop and set bool as false
        // that bool will skip the if stat above and end up in this spot anyways, to clean up the resources
        try
        {
            // clean up resources
            if(socket != null)
                socket.close();
            if(out_object != null)
                out_object.close();
            if(in_object != null)
                in_object.close();
        }
        catch (IOException ex)
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
        // </editor-fold>
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
        try
        {
            // write file with path and data
            Files.write(new File(filename).toPath(), data);
        }
        catch (IOException ex)
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    static Chunk createChunk(byte[] temp, int seq, Key skey)
    {
        // create CRC32
        int crc32 = generateCRC32(temp);
        // encrypt data
        temp = encryptData("AES", skey, temp);
        // return chunk
        return new Chunk(seq, temp, crc32);
    }

    static AckMessage sendReceiveChunk(Chunk chunk, ObjectInputStream in_object, ObjectOutputStream out_object)
    {
        AckMessage ack = null;

        try
        {
            // send chunk
            out_object.writeObject(chunk);
            // get back ACK
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
        // get object to create key
        KeyGenerator keygen = null;

        try
        {
            // generator created for AES
            keygen = KeyGenerator.getInstance(type.toUpperCase().trim());
        }
        catch (NoSuchAlgorithmException ex)
        {
            Logger.getLogger(FileTransfer.class.getName()).log(Level.SEVERE, null, ex);
        }
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
        // cipher to do encrypting
        Cipher cipher = null;
        // temp byte array
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

        // return excrypted data
        return temp;
    }

    static byte[] decryptData(String instance, Key key, byte[] data)
    {
        // cipher to de decryption
        Cipher cipher = null;
        // temp array to hold bytes
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
        // return decrypted data
        return temp;
    }

    // <editor-fold desc="Exception Classes">
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

    public static class InvalidMessageException extends RuntimeException //Exception
    {
        public InvalidMessageException(String message)
        {
            super(message);
        }

        public InvalidMessageException(Throwable cause)
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

    // </editor-fold>
}


