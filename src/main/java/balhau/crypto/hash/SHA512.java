package balhau.crypto.hash;

import balhau.utils.Mask;

/**
 * Secure hash algorithm (SHA) versão 512 bits.<br/><br/>
 * <b>Referências:</b><br/>
 * <a href="http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf">Federal Information Processing Standards Publication 180-2 (fips180-2)</a><br/>
 * @author balhau
 *
 */
public class SHA512 extends SHA implements IHash{
	/*
	 * Constantes utililizadas para dispersão
	 */
	private long MH_0,MH_1,MH_2,MH_3,MH_4,MH_5,MH_6,MH_7;
	public SHA512(){
		init();
	}
	
	private void init(){
		BUFFERL=new long[]{0x6a09e667f3bcc908L,0xbb67ae8584caa73bL,0x3c6ef372fe94f82bL,0xa54ff53a5f1d36f1L,
				   0x510e527fade682d1L,0x9b05688c2b3e6c1fL,0x1f83d9abfb41bd6bL,0x5be0cd19137e2179L};
		tkonstl=new long[]{0x428a2f98d728ae22L,0x7137449123ef65cdL,0xb5c0fbcfec4d3b2fL,0xe9b5dba58189dbbcL,0x3956c25bf348b538L,0x59f111f1b605d019L,
	0x923f82a4af194f9bL,0xab1c5ed5da6d8118L,0xd807aa98a3030242L,0x12835b0145706fbeL,0x243185be4ee4b28cL,0x550c7dc3d5ffb4e2L,0x72be5d74f27b896fL,
	0x80deb1fe3b1696b1L,0x9bdc06a725c71235L,0xc19bf174cf692694L,0xe49b69c19ef14ad2L,0xefbe4786384f25e3L,0x0fc19dc68b8cd5b5L,0x240ca1cc77ac9c65L,
	0x2de92c6f592b0275L,0x4a7484aa6ea6e483L,0x5cb0a9dcbd41fbd4L,0x76f988da831153b5L,0x983e5152ee66dfabL,0xa831c66d2db43210L,0xb00327c898fb213fL,
	0xbf597fc7beef0ee4L,0xc6e00bf33da88fc2L,0xd5a79147930aa725L,0x06ca6351e003826fL,0x142929670a0e6e70L,0x27b70a8546d22ffcL,0x2e1b21385c26c926L,
	0x4d2c6dfc5ac42aedL,0x53380d139d95b3dfL,0x650a73548baf63deL,0x766a0abb3c77b2a8L,0x81c2c92e47edaee6L,0x92722c851482353bL,0xa2bfe8a14cf10364L,
	0xa81a664bbc423001L,0xc24b8b70d0f89791L,0xc76c51a30654be30L,0xd192e819d6ef5218L,0xd69906245565a910L,0xf40e35855771202aL,0x106aa07032bbd1b8L,
	0x19a4c116b8d2d0c8L,0x1e376c085141ab53L,0x2748774cdf8eeb99L,0x34b0bcb5e19b48a8L,0x391c0cb3c5c95a63L,0x4ed8aa4ae3418acbL,0x5b9cca4f7763e373L,
	0x682e6ff3d6b2b8a3L,0x748f82ee5defb2fcL,0x78a5636f43172f60L,0x84c87814a1f0ab72L,0x8cc702081a6439ecL,0x90befffa23631e28L,0xa4506cebde82bde9L,
	0xbef9a3f7b2c67915L,0xc67178f2e372532bL,0xca273eceea26619cL,0xd186b8c721c0c207L,0xeada7dd6cde0eb1eL,0xf57d4f7fee6ed178L,0x06f067aa72176fbaL,
	0x0a637dc5a2c898a6L,0x113f9804bef90daeL,0x1b710b35131c471bL,0x28db77f523047d84L,0x32caab7b40c72493L,0x3c9ebe0a15c9bebcL,0x431d67c49c100d4cL,
	0x4cc5d4becb3e42b6L,0x597f299cfc657e2aL,0x5fcb6fab3ad6faecL,0x6c44198c4a475817L
		};
	}
	
	private void initRegistos(){
		MH_0=BUFFER[0];
		MH_1=BUFFER[1];
		MH_2=BUFFER[2];
		MH_3=BUFFER[3];
		MH_4=BUFFER[4];
		MH_5=BUFFER[5];
		MH_6=BUFFER[6];
		MH_7=BUFFER[7];
		buffMSGL=new long[16];
		chBuff=new byte[128];
		pos=0;
	}
	
	private void processaBlock(){
		long[] buffSHA80=new long[80];
		long a,b,c,d,e,f,g,h,tmp1,tmp2;
//		System.out.println("SHA256___________________________________________________________");
		//passo 1 na especificação fips
		for(int i=0;i<16;i++){
			buffSHA80[i]=buffMSGL[i];
		}
				
		for(int i=16;i<80;i++){
			buffSHA80[i]=DELTA1(buffSHA80[i-2])+buffSHA80[i-7]+DELTA0(buffSHA80[i-15])+buffSHA80[i-16];
		}
//		System.out.println(ArrayUtils.ArrayIntHEXDesc(buffSHA80));
		//passo 2 na especificação fips
		a=MH_0;b=MH_1;c=MH_2;d=MH_3;e=MH_4;f=MH_5;g=MH_6;h=MH_7;
		//passo 3 na especificação fips
		for(int i=0;i<80;i++){
			tmp1=h+SUM1(e)+CH(e, f, g)+tkonstl[i]+buffSHA80[i];
			tmp2=SUM0(a)+MAJ(a, b, c);
			h=g;g=f;f=e;e=d+tmp1;d=c;c=b;b=a;a=tmp1+tmp2;
			System.out.println("I: +"+i+"\tA: "+_h(a)+"\tB: "+_h(b)+"\tC: "+_h(c)+"\tD: "+_h(d)+"\tE: "+_h(e)+"\tF: "+_h(f)+"\tG: "+_h(g)+"\tH: "+_h(h));
		}
		
		//passo 4 na especificação fips computação do valor intermédio de hash
		MH_0=a+MH_0;MH_1=b+MH_1;MH_2=c+MH_2;
		MH_3=d+MH_3;MH_4=e+MH_4;MH_5=MH_5+f;
		MH_6=g+MH_6;MH_7=h+MH_7;
//		System.out.println("END256___________________________________________________________");
	}
	
	public String hexDigest(){
		return _h(MH_0)+_h(MH_1)+_h(MH_2)+_h(MH_3)+
		_h(MH_4)+_h(MH_5)+_h(MH_6)+_h(MH_7);
	}
	
	public static String hash(String str){
		SHA512 sh=new SHA512();
		boolean vaz=!str.equals("");
		if(vaz)
			sh.update(str.getBytes());
		sh.finish();
		return sh.hexDigest();
	}
	
	public String encode(String str){
		boolean vaz=!str.equals("");
		initRegistos();
		if(vaz)
			this.update(str.getBytes());
		this.finish();
		return this.hexDigest();
	}
	
	public String encode(byte[] arr){
		initRegistos();
		if(arr!=null && arr.length!=0)
			this.update(arr);
		this.finish();
		return this.hexDigest();
	}
	
	public void finish(){
		long nbits=pos*8;
		int lzeros;
		int resto=(int)(pos%128);
		byte[] comp=new byte[16];
//		System.out.println("BBits: "+(int)nbits);
//		System.out.println("POS: "+pos);
		comp[15]=(byte)(nbits&Mask.MASK8);
		comp[14]=(byte)((nbits>>8)&Mask.MASK8);
		comp[13]=(byte)((nbits>>16)&Mask.MASK8);
		comp[12]=(byte)((nbits>>24)&Mask.MASK8);
		comp[11]=(byte)((nbits>>32)&Mask.MASK8);
		comp[10]=(byte)((nbits>>40)&Mask.MASK8);
		comp[9]=(byte)((nbits>>48)&Mask.MASK8);
		comp[8]=(byte)((nbits>>56)&Mask.MASK8);
		for(int i=0;i<8;i++){comp[i]=0;}
		if(resto<120){
			lzeros=120-resto;
		}
		else
		{
			lzeros=248-resto;
		}
		byte[] pad=new byte[lzeros+8];
		for(int i=0;i<lzeros;i++)
			pad[i]=padding[i];
		for(int i=lzeros;i<lzeros+8;i++){
			pad[i]=comp[i-lzeros];
		}
		update(pad);
//		System.out.println("Resto: "+resto);
//		System.out.println("PAD: "+ArrayUtils.ArrayCharDesc(pad));
//		System.out.println("ZEROS: "+lzeros);
//		System.out.println("PadL: "+pad.length);
//		System.out.println("Pos: "+pos);
	}
	
	public void update(byte[] ch){
//		System.out.println("______________________________________________________________________________________");
		int cmp=ch.length;
		int rsto=(int)(pos%128);
		int diff=128-rsto;
		int i;
		pos+=cmp;
		//System.out.println("Pos: "+pos);
		//Se o numero de elementos no array forem superiores ou iguais os elementos que faltam para formar
		//um bloco de 512 bits então procede-se à computação dos respectivos blocos
		if(cmp>=diff){
			for(i=0;i<diff;i++){
				chBuff[rsto+i]=ch[i];
			}
//			System.out.println("Diff: "+diff);
//			System.out.println("CMP: "+cmp);
//			System.out.println("Char: "+ArrayUtils.ArrayCharDesc(ch));
//			System.out.println("ChBuff: "+ArrayUtils.ArrayCharDesc(chBuff));
//			System.out.println("Resto: "+rsto);
			blockByteToLong(chBuff);
			processaBlock();
			rsto=0;
			for(i=diff;i+127<cmp;i+=128){
				rsto=0;
				for(int j=0;j<128;j++){
					chBuff[j]=ch[i+j];
				}
//				System.out.println("InnerLoopBuff: "+ArrayUtils.ArrayCharDesc(chBuff));
				blockByteToLong(chBuff);
				processaBlock();
			}
		}
		else {
			i=0;
		}
		for(int j=0;j<cmp-i;j++){
			chBuff[j+rsto]=ch[j+i];
		}
	}
	
	private long CH(long x,long y,long z){
		return (x&y)^((~x)&z);
	}
	
	private long MAJ(long x,long y,long z){
		return (x&y)^(x&z)^(y&z);
	}
	
	private long SUM0(long x){
		return (Long.rotateRight(x, 28)^Long.rotateRight(x, 34)^Long.rotateRight(x, 39));
	}
	
	private long SUM1(long x){
		return (Long.rotateRight(x, 14)^Long.rotateRight(x, 18)^Long.rotateRight(x, 41));
	}
	
	private long DELTA0(long x){
		return Long.rotateRight(x, 1)^Long.rotateRight(x, 8)^(x>>>7);
	}
	
	private long DELTA1(long x){
		return Long.rotateRight(x, 19)^Long.rotateRight(x, 61)^(x>>>6);
	}

	public byte[] digest() {
		// TODO Auto-generated method stub
		return null;
	}
}
