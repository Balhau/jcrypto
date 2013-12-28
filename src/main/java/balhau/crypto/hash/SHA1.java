package balhau.crypto.hash;


import balhau.utils.Mask;

/**
 * Algoritmo de Hash. Secure Hash Algorithm (SHA) desenvolvid pelo National Institute of Standards (NIST) para utilização conjunta
 * com o Digital Signature Algorithm (DSA). Publicado em 1993 no Federal Information Processing Standards, publicação 180 (FIPS PUB 180)
 * O comprimento da hash de saida é de 160 bits.<br/><br/>
 * <b>Referências:</b><br/>
 * <a href="http://www.itl.nist.gov/fipspubs/fip180-1.htm">Federal Information Processing Standards Publication 180</a><br/>
 * @author balhau
 *
 */
public class SHA1 extends SHA implements IHash{
	/**
	 * atributos de instância que representam as variáveis finais para cômputo do hash
	 */
	private int MH_0;
	private int MH_1;
	private int MH_2;
	private int MH_3;
	private int MH_4;
	/**
	 * Função de operações bitwise
	 * @param A {@link Integer} Inteiro de 32bits utilizado para a dispersão
	 * @param B {@link Integer} Inteiro de 32bits utilizdo para a dispersão
	 * @param C {@link Integer} Inteiro de 32bits utilizado para a dispersão
	 * @param i {@link Integer} Representa o índice da iteração. A confusão binária é feita em função do
	 * valor de i.
	 * @return {@link Integer} resultado da transformação sobre.
	 */
	private static int FTransfrom(int A,int B,int C,int i){
		//variaveis auxiliares de 64 bits para evitar overflow na soma de valores
		//de 32 bits
		long lA,lB,lC;
		lA=A;
		lB=B;
		lC=C;
		if(i<20) return (int)(((lA&lB)+((~lA)&lC))&Mask.MASK32);
		if(i<40) return (int)((lA^lB^lC)&Mask.MASK32);
		if(i<60) return (int)(((lA&lB)|(lA&lC)|(lB&lC))&Mask.MASK32);
		else return (int)((lA^lB^lC)&Mask.MASK32);
	}
	/**
	 * Método que efectua a criação da tabela de constantes
	 * @return {@link Integer[]} array de inteiros representando as constantes utilizadas no algoritmo
	 * SHA1 
	 */
	private static int[] buildKonstTable(){
		int[] kts=new int[80];
		for(int i=0;i<80;i++){
			if(i<20) kts[i]=0x5a827999;
			else if(i<40) kts[i]=0x6ed9eba1;
			else if(i<60) kts[i]=0x8f1bbcdc;
			else if(i<80) kts[i]=0xca62c1d6;
		}
		return kts;
	}
	/**
	 * Método que processa um bloco de 512bits, ou seja 64 caracteres 
	 */
	private void processaBlock(){
		int[] buffSHA80=new int[80];
		//Criação das variáveis temporárias
		int A,B,C,D,E;
		int temp;
		//Efectua a cópia dos valores presentes no buffer
		for(int i=0;i<16;i++){
			buffSHA80[i]=buffMSG[i];
		}
//		System.out.println("W: "+ArrayUtils.ArrayIntHEXDesc(buffMSG));
		//Computa os restantes valores de buffer
		for(int i=16;i<80;i++){
			buffSHA80[i]=Integer.rotateLeft(buffSHA80[i-16]^buffSHA80[i-14]^buffSHA80[i-8]^buffSHA80[i-3], 1);
		}
		A=MH_0;B=MH_1;C=MH_2;D=MH_3;E=MH_4;
		for(int i=0;i<80;i++){
			temp=((Integer.rotateLeft(A, 5)+FTransfrom(B, C, D, i)+E+buffSHA80[i]+tkonst[i])&Mask.MASK32);
			E=D;D=C;C=Integer.rotateLeft(B, 30);B=A;A=temp;
		}
		MH_0+=A;MH_1+=B;MH_2+=C;MH_3+=D;MH_4+=E;
	}
	/**
	 * Método que efectua a computação de um bloco de caracteres
	 * @param ch {@link char[]} Array de caracteres 
	 */
	public void update(byte[] ch){
//		System.out.println("______________________________________________________________________________________");
		int cmp=ch.length;
		int rsto=(int)(pos%64);
		int diff=64-rsto;
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
			blockByteToInt(chBuff);
			processaBlock();
			rsto=0;
			for(i=diff;i+63<cmp;i+=64){
				rsto=0;
				for(int j=0;j<64;j++){
					chBuff[j]=ch[i+j];
				}
//				System.out.println("InnerLoopBuff: "+ArrayUtils.ArrayCharDesc(chBuff));
				blockByteToInt(chBuff);
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
	
	/**
	 * Método que finaliza o cômputo da hash 
	 */
	public void finish(){
		long nbits=pos*8;
		int lzeros;
		int resto=(int)(pos%64);
		byte[] comp=new byte[8];
//		System.out.println("BBits: "+(int)nbits);
//		System.out.println("POS: "+pos);
		comp[7]=(byte)(nbits&Mask.MASK8);
		comp[6]=(byte)((nbits>>8)&Mask.MASK8);
		comp[5]=(byte)((nbits>>16)&Mask.MASK8);
		comp[4]=(byte)((nbits>>24)&Mask.MASK8);
		comp[3]=(byte)((nbits>>32)&Mask.MASK8);
		comp[2]=(byte)((nbits>>40)&Mask.MASK8);
		comp[1]=(byte)((nbits>>48)&Mask.MASK8);
		comp[0]=(byte)((nbits>>56)&Mask.MASK8);
		if(resto<56){
			lzeros=56-resto;
		}
		else
		{
			lzeros=120-resto;
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
	
	/**
	 * Construtor da classe
	 */
	public SHA1(){
		this.init();
	}
	
	private void init(){
		tkonst=buildKonstTable();
		buffMSG=new int[16];
		chBuff=new byte[64];
		pos=0;
		buildPadding();
		BUFFER=new int[]{0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};
		MH_0=BUFFER[0];
		MH_1=BUFFER[1];
		MH_2=BUFFER[2];
		MH_3=BUFFER[3];
		MH_4=BUFFER[4];
	}
	/**
	 * Método estático que codifica uma {@link String}. 
	 * @param str {@link String} a codificar
	 * @return Hash da {@link String};
	 */
	public static String hash(String str){
		SHA1 sh=new SHA1();
		boolean vaz=!str.equals("");
		if(vaz)
			sh.update(str.getBytes());
		sh.finish();
		return sh.hexDigest();
	}
	
	public String encode(String str){
		init();
		boolean vaz=!str.equals("");
		if(vaz)
			this.update(str.getBytes());
		this.finish();
		return this.hexDigest();
	}
	
	public String encode(byte[] str){
		init();
		if(str!=null && str.length!=0)
			this.update(str);
		this.finish();
		return this.hexDigest();
	}
	/**
	 * Método que devolve o valor até então computado da hash numa string hexadecimal
	 * @return {@link String} Hash em formato hexadecimal
	 */
	public String hexDigest(){
		String dig="";
		dig+=String.format("%08x",MH_0);
		dig+=String.format("%08x",MH_1);
		dig+=String.format("%08x",MH_2);
		dig+=String.format("%08x",MH_3);
		dig+=String.format("%08x",MH_4);
		return dig;
	}
	
	public byte[] digest() {
		byte[] dig=new byte[20];
		byte[] aux;
		int step;
		int[] blks=new int[]{MH_0,MH_1,MH_2,MH_3,MH_4};
		for(int i=0;i<blks.length;i++){
			aux=int32ToByte(blks[i]);
			step=i*4;
			dig[step]=aux[0];dig[step+1]=aux[1];dig[step+2]=aux[2];dig[step+3]=aux[3];
		}
		return dig;
	}
}
