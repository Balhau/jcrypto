package balhau.crypto.hash;

import balhau.utils.ArrayUtils;

/**
 * Algoritmo de Hash inventado por Ronald Rivest no MIT em 1992.
 * Referências, RFC 1321. 
 * Internet Security: Cryptographic Principles, Algorithms and Protocols
 * @author balhau
 */
public class MD5 extends HashFunction implements IHash{
	/**
	 * Constantes do algoritmo MD5
	 */
	private static long A=0x67452301L;
	private static long B=0xefcdab89L;
	private static long C=0x98badcfeL;
	private static long D=0x10325476L;
	private static long MASK32=0xFFFFFFFFL;
	public long[] _T;
	private long[] _buff;
	private long[] _svect={	7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
			                   	5,9,14,20, 	5,9,14,20, 	5,9,14,20, 	5,9,14,20,
			                   	4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
			                   	6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21};
	private long Ax;
	private long Bx;
	private long Cx;
	private long Dx;
	private byte[] btbuff;
	private long nbyts;
	private byte[] padding;
	
	/**
	 * Construtor da classe MD5
	 * @param msg {@link int[]} Array de inteiros representando a mensagem para a qual se pretende computar o hash
	 */
	public MD5(int[] msg){
		buildTable();
		this._buff=new long[16];
		resetBuff();
		buildPadding();
	}
	/**
	 * Construtor da classe MD5
	 * @param msg {@link String} String que representa a mensagem para a qual se pretende computar o hash
	 */
	public MD5(String msg){
		buildTable();
		this._buff=new long[16];
		resetBuff();
		buildPadding();
	}
	/**
	 * Construtor defeito. Neste caso a string para a qual queremos determinar o hash value é vazia
	 */
	public MD5(){
		this("");
	}
	
	
	private void buildPadding(){
		padding=new byte[64];
		for(int i=0;i<64;i++){
			if(i==0)
				padding[i]=(byte)0x80;
			else
				padding[i]=0;
		}
	}
	/**
	 * Little endian 32bit número.
	 * @param arr
	 */
	private void block8Toblock32(byte[] arr){
		//Caso em que existem mais do que 512 bits de informação para ler
//		System.out.println("LBufferI: "+ArrayUtils.ArrayLongHEXDesc(this._buff));
//		System.out.println("BBuffer: "+ArrayUtils.ArrayByteHexDesc(this.btbuff));
		for(int i=0,j=0;i<64;j++,i+=4){
			_buff[j]=	((((long)arr[i+3])<<24)	&0xFF000000)|
						((((long)arr[i+2])<<16)	&0x00FF0000)|
						((((long)arr[i+1])<<8) 	&0x0000FF00)|
						((((long)arr[i]))		&0x000000FF);
		}
//		System.out.println("LBufferE: "+ArrayUtils.ArrayLongHEXDesc(this._buff));
	}
	
	private void resetBuff(){
		this.btbuff=new byte[64];
		this.nbyts=0;
		for(int i=0;i<this._buff.length;i++)
			this._buff[i]=0;
		Ax=A;
		Bx=B;
		Cx=C;
		Dx=D;
	}
	
	private void buildTable(){
		this._T=new long[64];
		long mxint=(long)Math.pow(2, 32);
		for(int i=1;i<=64;i++){
			this._T[i-1]=(long)Math.floor(mxint*Math.abs(Math.sin(i)))&MASK32;
		}
	}
	
	private void mdcore(long[] block){
		long f,g;
		long Axx,Bxx,Cxx,Dxx;
		long Axxx,Bxxx,Cxxx,Dxxx;
		Axx=Ax;Bxx=Bx;Cxx=Cx;Dxx=Dx;
		Axxx=Axx;Bxxx=Bxx;Cxxx=Cxx;Dxxx=Dxx;
//		System.out.println("MDCORE INVOKED");
//		System.out.print("State info INIT: ");
//		System.out.println(Long.toHexString(Ax)+","+Long.toHexString(Bx)+","+Long.toHexString(Cx)+","+Long.toHexString(Dx));
//		System.out.println("A: "+Long.toHexString(Ax)+" B: "+Long.toHexString(Bx)+" C: "+Long.toHexString(Cx)+" D: "+Long.toHexString(Dx));
		for(int i=0;i<64;i++)
		{
			if(i%4==0){
				Axxx=Axx;
				Bxxx=Bxx;
				Cxxx=Cxx;
				Dxxx=Dxx;
			}
			if(i%4==1){
				Axxx=Dxx;
				Bxxx=Axx;
				Cxxx=Bxx;
				Dxxx=Cxx;
			}
			if(i%4==2){
				Axxx=Cxx;
				Bxxx=Dxx;
				Cxxx=Axx;
				Dxxx=Bxx;
			}
			if(i%4==3){
				Axxx=Bxx;
				Bxxx=Cxx;
				Cxxx=Dxx;
				Dxxx=Axx;
			}
			//Computa F
			if(i<16){
				f=F(Bxxx, Cxxx, Dxxx);
				g=i;
			}
			//Computa G
			else if(i<32){
				f=G(Bxxx,Cxxx,Dxxx);
				g=(5*i+1)%16;
			}
			//Computa H
			else if(i<48){
				f=H(Bxxx,Cxxx,Dxxx);
				g=(3*i+5)%16;
			}
			//Computa I
			else{
				f=I(Bxxx,Cxxx,Dxxx);
				g=(7*i)%16;
			}
			if(i%4==0){
				Axx=(Bxx+(Integer.rotateLeft((int)(Axx+f+_T[i]+_buff[(int)g]&MASK32), (int)_svect[i])))&MASK32;
			}
			if(i%4==1){
				Dxx=(Axx+(Integer.rotateLeft((int)(Dxx+f+_T[i]+_buff[(int)g]&MASK32), (int)_svect[i])))&MASK32;
			}
			if(i%4==2){
				Cxx=(Dxx+(Integer.rotateLeft((int)(Cxx+f+_T[i]+_buff[(int)g]&MASK32), (int)_svect[i])))&MASK32;
			}
			if(i%4==3){
				Bxx=(Cxx+(Integer.rotateLeft((int)(Bxx+f+_T[i]+_buff[(int)g]&MASK32), (int)_svect[i])))&MASK32;
			}
//			System.out.println("A: "+Long.toHexString(Axx)+" B: "+Long.toHexString(Bxx)+" C: "+Long.toHexString(Cxx)+" D: "+Long.toHexString(Dxx));
		}
//		System.out.println("State: "+Long.toHexString(Ax)+","+Long.toHexString(Bx)+","+Long.toHexString(Cx)+","+Long.toHexString(Dx));
//		System.out.println("Vals: "+Long.toHexString(Axx)+","+Long.toHexString(Bxx)+","+Long.toHexString(Cxx)+","+Long.toHexString(Dxx));
		
		Ax=(Axx+Ax)&MASK32;
		Bx=(Bxx+Bx)&MASK32;
		Cx=(Cxx+Cx)&MASK32;
		Dx=(Dxx+Dx)&MASK32;
//		System.out.print("State info END: ");
//		System.out.println(Long.toHexString(Ax)+","+Long.toHexString(Bx)+","+Long.toHexString(Cx)+","+Long.toHexString(Dx));
//		System.out.println("LAx:"+Long.toHexString(Ax)+"\t LBx:"+Long.toHexString(Bx)+"\t LCx:"+Long.toHexString(Cx)+"\t LDx:"+Long.toHexString(Dx));
		block8Toblock32(padding);
	}
	
	/**
	 * Método que computa o hash para uma string
	 * @param val {@link String} String para a qual o hash irá ser computado
	 * @return {@link String} Hash computado
	 */
	public static String hash(String val){
		MD5 ins=new MD5("");
		return ins.encode(val.getBytes());
	}
	
	public void update(byte[] bts){
//		System.out.println("Process INIT");
//		System.out.println("Block: "+ArrayUtils.ArrayCharDesc(bts));
//		System.out.println("Pos: "+nbyts);
		int pos=(int)(nbyts%64);
		int i=0;
		int comp=bts.length;
		nbyts+=comp; 
		int comPar=64-pos;
		if(comp>=comPar){
			for(int j=0;j<comPar;j++){
				this.btbuff[j+pos]=bts[j];
			}
			block8Toblock32(this.btbuff);
//			System.out.println("Long Buffer: "+ArrayUtils.ArrayLongHEXDesc(this._buff));
//			System.out.println("Binary Buffer: "+ArrayUtils.ArrayByteHexDesc(this.btbuff));
			mdcore(this._buff);
//			System.out.println("HexDump: "+hexDigest());
			for(i=comPar;i+63<comp;i+=64){
				for(int j=0;j<64;j++){
					this.btbuff[j]=bts[i+j];
				}
				block8Toblock32(this.btbuff);
//				System.out.println("Long Buffer: "+ArrayUtils.ArrayLongHEXDesc(this._buff));
//				System.out.println("Binary Buffer: "+ArrayUtils.ArrayByteHexDesc(this.btbuff));
				mdcore(this._buff);
//				System.out.println("HexDump: "+hexDigest());
			}
			pos=0;
		}
		else
		{
			i=0;
		}
		for(int j=0;j<comp-i;j++){
			this.btbuff[j+pos]=bts[j+i];
		}
//		System.out.println("Buff: "+ArrayUtils.ArrayCharDesc(this.btbuff));
//		System.out.println("Process END");
	}
	
	public void finish(){
		long bts=nbyts*8;
		byte[] aux=new byte[8];
		aux[0]=(byte) (bts&0xFFL);
		aux[1]=(byte) ((bts>>8)&0xFFL);
		aux[2]=(byte) ((bts>>16)&0xFFL);
		aux[3]=(byte) ((bts>>24)&0xFFL);
		aux[4]=(byte) ((bts>>32)&0xFFL);
		aux[5]=(byte) ((bts>>40)&0xFFL);
		aux[6]=(byte) ((bts>>48)&0xFFL);
		aux[7]=(byte) ((bts>>56)&0xFFL);
		int pdcomp=(int)(nbyts%64);
		int pos;
		 
		if(pdcomp<56){
			pos=56-pdcomp;
		}
		else
		{
			pos=120-pdcomp;
		}
		
		byte[] pad=new byte[pos+8];
		for(int i=0;i<pos;i++){
			pad[i]=padding[i];
		}
		for(int i=0;i<8;i++){
			pad[pos+i]=aux[i];
		}
//		System.out.println("Val: "+ArrayUtils.ArrayByteHexDesc(aux));
//		System.out.println("PADLength: "+pad.length);
//		System.out.println("PadV: "+ArrayUtils.ArrayByteHexDesc(pad));
//		System.out.println("POS: "+pos);
		update(pad);
	}
	
	public String hexDigest(){
		String hex="";
		hex+=String.format("%08x",Long.reverseBytes(Ax<<32)&MASK32);
		hex+=String.format("%08x",Long.reverseBytes(Bx<<32)&MASK32);
		hex+=String.format("%08x",Long.reverseBytes(Cx<<32)&MASK32);
		hex+=String.format("%08x",Long.reverseBytes(Dx<<32)&MASK32);
		return hex;
	}
	
	public byte[] digest(){
		byte[] out=new byte[16];
		long A=Long.reverseBytes(Ax<<32)&MASK32;
		long B=Long.reverseBytes(Bx<<32)&MASK32;
		long C=Long.reverseBytes(Cx<<32)&MASK32;
		long D=Long.reverseBytes(Dx<<32)&MASK32;
		byte[] Ab=long32ToByte(A);
		byte[] Bb=long32ToByte(B);
		byte[] Cb=long32ToByte(C);
		byte[] Db=long32ToByte(D);
		out[0]=Ab[0];out[1]=Ab[1];out[2]=Ab[2];out[3]=Ab[3];
		out[4]=Bb[0];out[5]=Bb[1];out[6]=Bb[2];out[7]=Bb[3];
		out[8]=Cb[0];out[9]=Cb[1];out[10]=Cb[2];out[11]=Cb[3];
		out[12]=Db[0];out[13]=Db[1];out[14]=Db[2];out[15]=Db[3];
		return out;
	}
	
	public String encode(byte[] val){
		resetBuff();
		update(val);
		finish();
		return hexDigest();
	}
	
	private long F(long x,long y,long z){
		return ((x&y)|((~x)&z))&MASK32;
	}
	
	private long G(long x,long y,long z){
		return ((x&z)|(y&(~z)))&MASK32;
	}
	
	private long H(long x,long y,long z){
		return (x^y^z)&MASK32;
	}
	
	private long I(long x,long y,long z){
		return (y^(x|(~z)))&MASK32;
	}
	
	public String encode(String msg) {
		return this.encode(msg.getBytes());
	}
}
