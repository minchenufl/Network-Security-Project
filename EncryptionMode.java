import java.util.Scanner;

/**
 * This class implements the encryption modes: CBC, OFB, CFB, CTR,
 * as well as the MAC in the form of CBC.
 * @author Min Chen
 *
 */
public class EncryptionMode 
{
  private TEA teaAlgo;
	private int[] v = new int[2];
	private int[] IV = new int[2];
	private byte[] IVBytes;
	private int kForCFB;
	private String initialVector;
	
	public EncryptionMode(TEA algo)   //for MAC, no initial vector is used
	{
		this.teaAlgo = algo;
	}
	
	public EncryptionMode(String initialVector, TEA algo)
	{
		initialVector = wrapIV(initialVector);
		this.initialVector = initialVector;
		IVBytes = initialVector.getBytes();
		IV[0] = (IVBytes[0] & 0xff) | ((IVBytes[1] & 0xff) << 8) | ((IVBytes[2] & 0xff) << 16) | ((IVBytes[3] & 0xff) << 24);
		IV[1] = (IVBytes[4] & 0xff) | ((IVBytes[5] & 0xff) << 8) | ((IVBytes[6] & 0xff) << 16) | ((IVBytes[7] & 0xff) << 24);		
		this.teaAlgo = algo;
	}
	
	/**
	 * CBC encryption.
	 * @param plainText is the plainText represented by integers
	 */
	public void CBC_Encrypt(int[] plainText)
	{
		v[0]=IV[0]^plainText[0];
		v[1]=IV[1]^plainText[1];
		teaAlgo.encryptBlock(v);                                /* encrypt the first block*/
		plainText[0] = v[0];
		plainText[1] = v[1];
		
		for(int i=1;i<plainText.length/2;i++)
		{
			v[0] = plainText[2*i] ^ plainText[2*i-2];
			v[1] = plainText[2*i+1] ^ plainText[2*i-1];
			teaAlgo.encryptBlock(v);
			plainText[2*i] = v[0];
			plainText[2*i+1] = v[1];
		}
	}
	
	/**
	 * CBC decryption.
	 * @param cipherText is the ciphertext represented by integers
	 */
	public void CBC_Decrypt(int[] cipherText)
	{
		for(int i=(cipherText.length/2-1); i>0; i--)
		{
			v[0] = cipherText[2*i];
			v[1] = cipherText[2*i+1];
			teaAlgo.decryptBlock(v);
			cipherText[2*i] = v[0] ^ cipherText[2*i-2];
			cipherText[2*i+1] = v[1] ^ cipherText[2*i-1];	
		}
		
		v[0] = cipherText[0];
		v[1] = cipherText[1];
		teaAlgo.decryptBlock(v);
		cipherText[0] = v[0] ^ IV[0];
		cipherText[1] = v[1] ^ IV[1];
	}
	
	/**
	 * OFB encryption.
	 * @param plainText is the plaintext represented by integers 
	 */
	public void OFB_Encrypt(int[] plainText)
	{
		for(int i=0; i<plainText.length/2; i++)
		{
			v[0] = IV[0];
			v[1] = IV[1];
			teaAlgo.encryptBlock(v);
			plainText[2*i] ^= v[0];
			plainText[2*i+1] ^= v[1];
		}	
	}
	
	/**
	 * OFB decryption
	 * @param cipherText is the ciphtertext represented by integers
	 */
	public void OFB_Decrypt(int[] cipherText)
	{
		for(int i=0; i<cipherText.length/2; i++)
		{
			v[0] = IV[0];
			v[1] = IV[1];
			teaAlgo.encryptBlock(v);
			cipherText[2*i] ^= v[0];
			cipherText[2*i+1] ^= v[1];
		}	
	}

	/**
	 * CFB encryption.
	 * @param plainText is the plaintext represented by bytes
	 */
	public void CFB_Encrypt(byte[] plainText)
	{
		Scanner in = new Scanner(System.in);
		System.out.print("Choose the value of k for CFB 8/16/32/64: ");
		kForCFB = in.nextInt();              // kForCFB is the number of bits IV is shifted each time
		
		int[] IVCopy = new int[2];
		IVCopy[0] = IV[0];
		IVCopy[1] = IV[1];
		getCurrentVector(v, IVBytes);
		teaAlgo.encryptBlock(v); 
		
		if(kForCFB==8)
		{
			plainText[0] = (byte) ((plainText[0] & 0xff) ^ (v[1]>>>24));
			
		
			for(int i=1; i<plainText.length; i++)
			{	
				for(int j=IVBytes.length-1; j>0; j--)
				{
					IVBytes[j] = IVBytes[j-1];
				}
				
				IVBytes[0] = plainText[i-1];
				getCurrentVector(v, IVBytes);
				teaAlgo.encryptBlock(v);
				plainText[i] = (byte) ((plainText[i] & 0xff) ^ (v[1]>>>24));
				
				//System.out.printf("%x\n", plainText[i]);
			}
		}
		
		else if(kForCFB==16)
		{
			plainText[0] ^= (v[1] & 0x00ff0000)>>16;
			plainText[1] ^= v[1]>>24;
		
			for(int i=1; i<plainText.length/2-1; i++)
			{
				for(int j=IVBytes.length-1; j>1; j--)
				{
					IVBytes[j] = IVBytes[j-2];
				}
				IVBytes[1] = plainText[2*i-1];
				IVBytes[0] = plainText[2*i-2];
				getCurrentVector(v, IVBytes);
				
				teaAlgo.encryptBlock(v);
				plainText[2*i] ^= (v[1] & 0x00ff0000)>>>16;
				plainText[2*i+1] ^= v[1]>>>24;
			}
		}
		
		else if(kForCFB==32)
		{
			plainText[0] ^= (v[1] & 0xff);
			plainText[1] ^= (v[1] & 0xff00) >>>8;
			plainText[2] ^= (v[1] & 0xff0000) >>>16;
			plainText[3] ^= (v[1] & 0xff000000) >>>24;
		
			for(int i=1; i<plainText.length/4-1; i++)
			{
				v[1] = IVCopy[1] = IVCopy[0];
				v[0] = IVCopy[0] = (plainText[4*i-4] & 0xff) | ((plainText[4*i-3] & 0xff) << 8) | ((plainText[4*i-2] & 0xff) << 16) |((plainText[4*i-1] & 0xff) << 24);
				
				teaAlgo.encryptBlock(v);
				
				plainText[4*i] ^= (v[1] & 0xff);
				plainText[4*i+1] ^= (v[1] & 0xff00) >>>8;
				plainText[4*i+2] ^= (v[1] & 0xff0000) >>>16;
				plainText[4*i+3] ^= (v[1] & 0xff000000) >>>24;
			}
		}
		
		else if(kForCFB==64)
		{
			plainText[0] ^= (v[0] & 0xff);
			plainText[1] ^= (v[0] & 0xff00) >>>8;
			plainText[2] ^= (v[0] & 0xff0000) >>>16;
			plainText[3] ^= (v[0] & 0xff000000) >>>24;
		
			plainText[4] ^= (v[1] & 0xff);
			plainText[5] ^= (v[1] & 0xff00) >>>8;
			plainText[6] ^= (v[1] & 0xff0000) >>>16;
			plainText[7] ^= (v[1] & 0xff000000) >>>24;

			for(int i=1; i<plainText.length/8-1; i++)
			{
				v[0] = (plainText[8*i-8] & 0xff) | ((plainText[8*i-7] & 0xff) <<8) | ((plainText[8*i-6] & 0xff) <<16) |((plainText[8*i-5] & 0xff)<<24);
				v[1] = (plainText[8*i-4] & 0xff) | ((plainText[8*i-3] & 0xff) <<8) | ((plainText[8*i-2] & 0xff) <<16) |((plainText[8*i-1] & 0xff)<<24);
				
				teaAlgo.encryptBlock(v);
				
				plainText[8*i] ^= (v[0] & 0xff);
				plainText[8*i+1] ^= (v[0] & 0xff00) >>>8;
				plainText[8*i+2] ^= (v[0] & 0xff0000) >>>16;
				plainText[8*i+3] ^= (v[0] & 0xff000000) >>>24;
			
				plainText[8*i+4] ^= (v[1] & 0xff);
				plainText[8*i+5] ^= (v[1] & 0xff00) >>>8;
				plainText[8*i+6] ^= (v[1] & 0xff0000) >>>16;
				plainText[8*i+7] ^= (v[1] & 0xff000000) >>>24;
			}
		}
		
		else
		{
			System.err.println("INVALID VALUE OF k");
			System.exit(1);
		}
	}
	
	/**
	 * CFB decryption.
	 * @param cipherText is the ciphtertext represented by bytes 
	 */
	public void CFB_Decrypt(byte[] cipherText)
	{
		byte[] plainText = new byte[cipherText.length];
		int[] IVCopy = new int[2];
		IVCopy[0] = IV[0];
		IVCopy[1] = IV[1];
		
		IVBytes = initialVector.getBytes();
		getCurrentVector(v, IVBytes);
		teaAlgo.encryptBlock(v);
		
		if(kForCFB==8)
		{
			plainText[0] = (byte) ((cipherText[0]&0xff) ^ (v[1]>>>24)); 
			for(int i=1; i<cipherText.length; i++)
			{	
				for(int j=IVBytes.length-1; j>0; j--)
				{
					IVBytes[j] = IVBytes[j-1];
				}
				
				IVBytes[0] = cipherText[i-1];
				getCurrentVector(v, IVBytes);
				teaAlgo.encryptBlock(v);
				plainText[i] = (byte) ((cipherText[i]&0xff) ^ (v[1]>>>24));

			}
		}
		
		else if(kForCFB==16)
		{
			plainText[0] = (byte) (cipherText[0] ^ ((v[1] & 0x00ff0000)>>16));
			plainText[1] = (byte) (cipherText[1] ^ (v[1]>>24));
		
			for(int i=1; i<cipherText.length/2-1; i++)
			{
				for(int j=IVBytes.length-1; j>1; j--)
				{
					IVBytes[j] = IVBytes[j-2];
				}
				IVBytes[1] = cipherText[2*i-1];
				IVBytes[0] = cipherText[2*i-2];
				getCurrentVector(v, IVBytes);
				teaAlgo.encryptBlock(v);
				plainText[2*i] = (byte) (cipherText[2*i] ^ ((v[1] & 0x00ff0000)>>16));
				plainText[2*i+1] = (byte) (cipherText[2*i+1] ^ (v[1]>>24));
			}
		}
		
		else if(kForCFB==32)
		{
			plainText[0] = (byte) (cipherText[0] ^ (v[1] & 0xff));
			plainText[1] = (byte) (cipherText[1] ^ ((v[1] & 0xff00) >>>8));
			plainText[2] = (byte) (cipherText[2] ^ ((v[1] & 0xff0000) >>>16));
			plainText[3] = (byte) (cipherText[3] ^ ((v[1] & 0xff000000) >>>24));
		
			for(int i=1; i<plainText.length/4-1; i++)
			{
				v[1] = IVCopy[1] = IVCopy[0];
				v[0] = IVCopy[0] = (cipherText[4*i-4] & 0xff) | ((cipherText[4*i-3] & 0xff) << 8) | ((cipherText[4*i-2] & 0xff) << 16) |((cipherText[4*i-1] & 0xff) << 24);
				
				teaAlgo.encryptBlock(v);
				
				plainText[4*i] = (byte) (cipherText[4*i] ^ (v[1] & 0xff));
				plainText[4*i+1] = (byte) (cipherText[4*i+1] ^ ((v[1] & 0xff00) >>>8));
				plainText[4*i+2] = (byte) (cipherText[4*i+2] ^ ((v[1] & 0xff0000) >>>16));
				plainText[4*i+3] = (byte) (cipherText[4*i+3] ^ ((v[1] & 0xff000000) >>>24));
			}
		}
		
		else if(kForCFB==64)
		{
			plainText[0] = (byte) (cipherText[0] ^ (v[0] & 0xff));
			plainText[1] = (byte) (cipherText[1] ^ ((v[0] & 0xff00) >>>8));
			plainText[2] = (byte) (cipherText[2] ^ ((v[0] & 0xff0000) >>>16));
			plainText[3] = (byte) (cipherText[3] ^ ((v[0] & 0xff000000) >>>24));
		
			plainText[4] = (byte) (cipherText[4] ^ (v[1] & 0xff));
			plainText[5] = (byte) (cipherText[5] ^ ((v[1] & 0xff00) >>>8));
			plainText[6] = (byte) (cipherText[6] ^ ((v[1] & 0xff0000) >>>16));
			plainText[7] = (byte) (cipherText[7] ^ ((v[1] & 0xff000000) >>>24));

			for(int i=1; i<plainText.length/8-1; i++)
			{
				v[0] = (cipherText[8*i-8] & 0xff) | ((cipherText[8*i-7] & 0xff) << 8) | ((cipherText[8*i-6] & 0xff) << 16) |((cipherText[8*i-5] & 0xff) << 24);
				v[1] = (cipherText[8*i-4] & 0xff) | ((cipherText[8*i-3] & 0xff) << 8) | ((cipherText[8*i-2] & 0xff) << 16) |((cipherText[8*i-1] & 0xff) << 24);
				
				teaAlgo.encryptBlock(v);
				
				plainText[8*i] = (byte) (cipherText[8*i] ^ (v[0] & 0xff));
				plainText[8*i+1] = (byte) (cipherText[8*i+1] ^ ((v[0] & 0xff00) >>>8));
				plainText[8*i+2] = (byte) (cipherText[8*i+2] ^ ((v[0] & 0xff0000) >>>16));
				plainText[8*i+3] = (byte) (cipherText[8*i+3] ^ ((v[0] & 0xff000000) >>>24));
			
				plainText[8*i+4] = (byte) (cipherText[8*i+4] ^ (v[1] & 0xff));
				plainText[8*i+5] = (byte) (cipherText[8*i+5] ^ ((v[1] & 0xff00) >>>8));
				plainText[8*i+6] = (byte) (cipherText[8*i+6] ^ ((v[1] & 0xff0000) >>>16));
				plainText[8*i+7] = (byte) (cipherText[8*i+7] ^ ((v[1] & 0xff000000) >>>24));
			}
		}
		
		for(int i=0; i<cipherText.length; i++)
			cipherText[i] = plainText[i];
	}
	
	/**
	 * CTR encryption.
	 * @param plainText is the plaintext represented by integers
	 */
	public void CTR_Encrypt(int[] plainText)
	{
		long combinedIV;
		v[0] = IV[0];
		v[1] = IV[1];
		for(int i=1; i<plainText.length/2; i++)
		{
			teaAlgo.encryptBlock(v);
			plainText[2*i] ^= v[0];
			plainText[2*i] ^= v[1];
			
			combinedIV = v[1];
			combinedIV = (v[0] | (combinedIV<<32)) + 1;
			v[0] = (int) (combinedIV & 0xffffffff);
			v[1] = (int) (combinedIV >>32);
		}
	}
	
	/**
	 * CTR decryption.
	 * @param cipherText is the ciphtertext represented by integers
	 */
	public void CTR_Decrypt(int[] cipherText)
	{
		long combinedIV;
		v[0] = IV[0];
		v[1] = IV[1];
		for(int i=1; i<cipherText.length/2; i++)
		{
			teaAlgo.encryptBlock(v);
			cipherText[2*i] ^= v[0];
			cipherText[2*i] ^= v[1];
			
			combinedIV = v[1];
			combinedIV = (v[0] | (combinedIV<<32)) + 1;
			v[0] = (int) (combinedIV & 0xffffffff);
			v[1] = (int) (combinedIV >>32);
		}
	}
	
	
	/**
	 * MAC verification of a message using the the last block of its CBC encryption.
	 * @param plainText is the plaintext represented by integers
	 */
	public void MAC(int[] plainText)
	{
		v[0]=IV[0]^plainText[0];
		v[1]=IV[1]^plainText[1];
		teaAlgo.encryptBlock(v);                                /* encrypt the first block*/
		plainText[0] = v[0];
		plainText[1] = v[1];
		
		for(int i=1;i<plainText.length/2;i++)
		{
			v[0] = plainText[2*i] ^ plainText[2*i-2];
			v[1] = plainText[2*i+1] ^ plainText[2*i-1];
			teaAlgo.encryptBlock(v);
			plainText[2*i] = v[0];
			plainText[2*i+1] = v[1];
		}
	}
	
	/**
	 * Wrap the original initial vector to 64-bit.
	 * @param initialVector is the initial vector entered by the user
	 * @return the wrapped initial vector that consists of 64 characters
	 */
	public static String wrapIV(String initialVector)
	{
		int paddingLength;
		if(initialVector.length()>8)
			initialVector = initialVector.substring(0, 8);
		else
			{
				paddingLength = 8 - initialVector.length();
				for(int i=0; i<paddingLength; i++)
				{
					initialVector += "@";
				}
			}
		return initialVector;
	}
	
	/**
	 * Convert the value of vectors in bytes into two integers, this is used only in CFB.
	 * @param v stores the value of the vector as two integer
	 * @param IVBytes stores the value of the vector as an array of bytes
	 */
	public static void getCurrentVector(int[]v, byte[] IVBytes)
	{
		v[0] = (IVBytes[0] & 0xff) | ((IVBytes[1] & 0xff) << 8) | ((IVBytes[2] & 0xff) << 16) | ((IVBytes[3] & 0xff) << 24);
		v[1] = (IVBytes[4] & 0xff) | ((IVBytes[5] & 0xff) << 8) | ((IVBytes[6] & 0xff) << 16) | ((IVBytes[7] & 0xff) << 24);
		
	}
	
	/**
	 * Get the value of K in CFB.
	 * @return the value of K
	 */
	public int getK()
	{
		return kForCFB;
	}
	
}
