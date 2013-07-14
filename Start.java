import java.io.UnsupportedEncodingException;
import java.util.Random;
import java.util.Scanner;

/**
 * This project implements the basic encryption modes for symmetric block ciphers.
 * @author Min Chen
 */
public class Start 
{
  public static void main(String[] args) throws UnsupportedEncodingException
	{
		String[] temp;
		
		temp = args[0].split("=");
		int mode = Integer.parseInt(temp[1]);        //chose of modes: 1.CBC 2.OFB 3.CFB 4.CTR 5. MAC
		
		temp = args[1].split("=");                   //which block is modified by the adversary (block# starts from 1)
		int eblock = Integer.parseInt(temp[1]);
		
		Scanner in = new Scanner(System.in);
		
		if(mode==1 || mode==2 || mode==3 || mode==4)
		{
			System.out.print("Enter IV: ");
			String initialVector = in.nextLine();
			
			System.out.print("Enter PassPhrase: ");
			String passPhrase = in.nextLine();
			
			System.out.print("Input Message: ");
			String message = in.nextLine();
			
			message = messageWrap(message);
			byte[] messageBytes = message.getBytes();
			int [] plainText = messageTransform(message);
			
						
			TEA teaAlgo = new TEA (passPhrase);        //object of TEA algorithm
			EncryptionMode executor = new EncryptionMode(initialVector, teaAlgo);
			
			if(mode==1)                                //encryption
				executor.CBC_Encrypt(plainText);
			if(mode==2)
				executor.OFB_Encrypt(plainText);
			if(mode==3)
				executor.CFB_Encrypt(messageBytes);
			if(mode==4)
				executor.CTR_Encrypt(plainText);
			
			if(eblock>0)                               //adversary modifies the corresponding block of ciphertext
			{
				Random gen = new Random();

				if(mode==3)
				{
					int kForCFB = executor.getK();
					if(kForCFB==8)
						messageBytes[eblock-1] ^= gen.nextInt();
					else if(kForCFB==16)
					{
						messageBytes[2*eblock-2] ^= gen.nextInt();
						messageBytes[2*eblock-1] ^= gen.nextInt();
					}
					else if(kForCFB==32)
					{
						messageBytes[4*eblock-4] ^= gen.nextInt();
						messageBytes[4*eblock-3] ^= gen.nextInt();
						messageBytes[4*eblock-2] ^= gen.nextInt();
						messageBytes[4*eblock-1] ^= gen.nextInt();
					}
					
					else if(kForCFB==64)
					{
						messageBytes[8*eblock-8] ^= gen.nextInt();
						messageBytes[8*eblock-7] ^= gen.nextInt();
						messageBytes[8*eblock-6] ^= gen.nextInt();
						messageBytes[8*eblock-5] ^= gen.nextInt();
						messageBytes[8*eblock-4] ^= gen.nextInt();
						messageBytes[8*eblock-3] ^= gen.nextInt();
						messageBytes[8*eblock-2] ^= gen.nextInt();
						messageBytes[8*eblock-1] ^= gen.nextInt();						
					}
				}
				else
				{
					plainText[2*eblock-2] ^= gen.nextInt();
					plainText[2*eblock-1] ^= gen.nextInt();	
				}
			}
			
			/*else if(eblock > blockNumber)
			{
				System.err.println("BLOCK NUMBER TOO LARGE!");
				System.exit(1);
			}*/
			
			if(mode==1)                                      //decryption
				executor.CBC_Decrypt(plainText);
			if(mode==2)
				executor.OFB_Decrypt(plainText);
			if(mode==3)
				executor.CFB_Decrypt(messageBytes);
			if(mode==4)
				executor.CTR_Decrypt(plainText);
			if(mode==3)
				message = new String (messageBytes, "UTF-8");
			else
				message = messageRecover(plainText);
			
			String[] tempMessages = message.split("/");
			String decryptedMessage = tempMessages[0];
			System.out.println(decryptedMessage);		
		}
		
		
		else if(mode==5)                                     //MAC verification
		{
			System.out.print("Enter PassPhrase: ");
			String passPhrase = in.nextLine();
			
			System.out.print("Input Message: ");
			String message = in.nextLine();
			
			message = messageWrap(message);
			int blockNumber = message.length()/8;
			
			int[] plainText = messageTransform(message);
			int[] messageCopy = new int[2*blockNumber];
			
			for(int i=0; i<2*blockNumber; i++)
			{
				messageCopy[i] = plainText[i];
			}
			
						
			TEA teaAlgo = new TEA (passPhrase);
			EncryptionMode executor = new EncryptionMode(teaAlgo);
			
			executor.MAC(plainText);
			
			
			if(eblock>0 && eblock<blockNumber)
			{
				Random gen = new Random();
				int low = gen.nextInt();
				int high = gen.nextInt();
				messageCopy[2*eblock-2] ^= low;
				messageCopy[2*eblock-1] ^= high;	
			}
			
			else if(eblock>=blockNumber) 
			{
				System.err.println("BLOCK NUMBER TOO LARGE!");
				System.exit(1);
			}
			
			executor.MAC(messageCopy);
			
			if(messageCopy[2*blockNumber-2] == plainText[2*blockNumber-2] && messageCopy[2*blockNumber-1] == plainText[2*blockNumber-1] )
				System.out.println("THE MESSAGE HAS NOT BEEN MODIFIED.");
			else 
				System.out.println("ALTER! THE MESSAGE HAS BEEN MODIFIED!");
		}
		
		else
		{
			System.err.println("NO SUCH A MODE!");
			System.exit(1);
		}
	}
	
	/**
	 * Wrap the message to a multiple of 64-bit blocks.
	 * @param message the original message entered by the user
	 * @return the wrapped message
	 */
	public static String messageWrap(String message)            
	{
		int messagePadding = 8 - message.length() % 8;
		
		//System.out.println(messagePadding);
		
		if(messagePadding != 0)
		{
			message += "/";
			
			for(int i=0; i<messagePadding-1; i++)
				message += "@";
		}
		
		return message;
	}
	
	/**
	 * Transform the string message into 32-bit blocks.
	 * @param message the wrapped message
	 * @return the array of 32-bit blocks
	 */
	public static int[] messageTransform(String message)
	{
		byte[] messageBytes = message.getBytes();

		int blockNumber = messageBytes.length/8;
		
		int[] plainText = new int[blockNumber*2];

		for(int i=0; i<blockNumber*2; i++)
			plainText[i] = 0;
		
		for(int i=0; i<blockNumber*2; i++)
			plainText[i] = (messageBytes[4*i] & 0xff) | ((messageBytes[4*i+1] & 0xff) <<8) | ((messageBytes[4*i+2] & 0xff) << 16) | ((messageBytes[4*i+3] & 0xff) << 24);

		return plainText;
	}
	
	/**
	 * Retrieve the original message from the decrypted bytes.
	 * @param cipherText is the array of decrypted bytes
	 * @return the recovered string
	 * @throws UnsupportedEncodingException
	 */
	public static String messageRecover(int[] cipherText) throws UnsupportedEncodingException
	{
		byte[] messageBytes = new byte[4*cipherText.length];
		for(int i=0; i<messageBytes.length; i++)
		{
			switch(i%4)
			{
			case 0: messageBytes[i] = (byte) (cipherText[i/4] & 0xff); break;
			case 1: messageBytes[i] = (byte) ((cipherText[i/4] & 0xff00)>>8); break;
			case 2: messageBytes[i] = (byte) ((cipherText[i/4] & 0xff0000)>>16); break;
			case 3: messageBytes[i] = (byte) ((cipherText[i/4] & 0xff000000)>>24); break;
			}
			
		}
		return new String(messageBytes, "UTF-8");
	}

}
