package balhau.crypto.hash;

import balhau.utils.Mask;
import balhau.matematica.MathUtils;

/***
 * Implementação do algoritmo SHA versão 256.<br/><br/>
 * <b>Referências:</b><br/>
 * <a href="http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf">Federal Information Processing Standards Publication 180-2 (fips180-2)</a><br/>
 * @author balhau
 *
 */
public class SHA256 extends SHA implements IHash{
	/*
	 * Estas constantes são a represntação hexadecimal da parte fraccionária das raizes dos seguintes números primos
	 *  2, 3, 5, 7, 11, 13, 17, 19
	 */
	/**
	 * Tabela com as 64 constantes construidas a partir dos 32 bits da raiz cubica dos primeiros 64 numeros
	 * primos 
	 */
	
	private int MH_0,MH_1,MH_2,MH_3,MH_4,MH_5,MH_6,MH_7;
	/**
	 * Construtor do objecto
	 */
	public SHA256(){
		init();
	}
	
	private void init(){
		BUFFER=new int[]{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
		tkonst=MathUtils.fpndcr(64);
		buildPadding();
		initRegistos();	
	}
	
	/**
	 * Método que efectua o processamento dos blocos de mensagens
	 */
	private void processaBlock(){
		int[] buffSHA80=new int[64];
		int a,b,c,d,e,f,g,h,tmp1,tmp2;
//		System.out.println("SHA256___________________________________________________________");
		//passo 1 na especificação fips
		for(int i=0;i<16;i++){
			buffSHA80[i]=buffMSG[i];
		}
				
		for(int i=16;i<64;i++){
			buffSHA80[i]=DELTA1(buffSHA80[i-2])+buffSHA80[i-7]+DELTA0(buffSHA80[i-15])+buffSHA80[i-16];
		}
//		System.out.println(ArrayUtils.ArrayIntHEXDesc(buffSHA80));
		//passo 2 na especificação fips
		a=MH_0;b=MH_1;c=MH_2;d=MH_3;e=MH_4;f=MH_5;g=MH_6;h=MH_7;
		//passo 3 na especificação fips
		for(int i=0;i<64;i++){
			tmp1=h+SUM1(e)+CH(e, f, g)+tkonst[i]+buffSHA80[i];
			tmp2=SUM0(a)+MJ(a, b, c);
			h=g;g=f;f=e;e=d+tmp1;d=c;c=b;b=a;a=tmp1+tmp2;
//			System.out.println("I: +"+i+"\tA: "+_h(a)+"\tB: "+_h(b)+"\tC: "+_h(c)+"\tD: "+_h(d)+"\tE: "+_h(e)+"\tF: "+_h(f)+"\tG: "+_h(g)+"\tH: "+_h(h));
		}
		
		//passo 4 na especificação fips computação do valor intermédio de hash
		MH_0=a+MH_0;MH_1=b+MH_1;MH_2=c+MH_2;
		MH_3=d+MH_3;MH_4=e+MH_4;MH_5=MH_5+f;
		MH_6=g+MH_6;MH_7=h+MH_7;
//		System.out.println("END256___________________________________________________________");
	}
	
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
	 * Método que devolve a string hexadecimal com o valor da hash computada
	 * @return {@link String} valor da hash em hexadecimal
	 */
	public String hexDigest(){
		return Integer.toHexString(MH_0)+Integer.toHexString(MH_1)+Integer.toHexString(MH_2)+Integer.toHexString(MH_3)+
		Integer.toHexString(MH_4)+Integer.toHexString(MH_5)+Integer.toHexString(MH_6)+Integer.toHexString(MH_7);
	}
	
	public static String hash(String str){
		SHA256 sh=new SHA256();
		boolean vaz=!str.equals("");
		if(vaz)
			sh.update(str.getBytes());
		sh.finish();
		return sh.hexDigest();
	}
	
	public String encode(String str){
		boolean vaz=!str.equals("");
		if(vaz)
			this.update(str.getBytes());
		this.finish();
		return this.hexDigest();
	}
	
	public String encode(byte[] arr){
		if(arr!=null && arr.length!=0)
			this.update(arr);
		this.finish();
		return this.hexDigest();
	}
	
	/**
	 * Método que inicializa os registos
	 */
	private void initRegistos(){
		MH_0=BUFFER[0];
		MH_1=BUFFER[1];
		MH_2=BUFFER[2];
		MH_3=BUFFER[3];
		MH_4=BUFFER[4];
		MH_5=BUFFER[5];
		MH_6=BUFFER[6];
		MH_7=BUFFER[7];
		buffMSG=new int[16];
		chBuff=new byte[64];
		pos=0;
	}
	
	private int CH(int x,int y,int z){
		return (x&y)^((~x)&z);
	}
	
	private int MJ(int x,int y,int z){
		return (x&y)^(x&z)^(y&z);
	}
	
	private int SUM0(int x){
		return (Integer.rotateRight(x, 2)^Integer.rotateRight(x,13)^Integer.rotateRight(x, 22));
	}
	
	private int SUM1(int x){
		return (Integer.rotateRight(x, 6)^Integer.rotateRight(x, 11)^Integer.rotateRight(x, 25));
	}
	
	private int DELTA0(int x){
		return (Integer.rotateRight(x, 7)^Integer.rotateRight(x, 18)^(x>>>3));
	}
	
	private int DELTA1(int x){
		return (Integer.rotateRight(x, 17)^Integer.rotateRight(x, 19)^(x>>>10));
	}

	public byte[] digest() {
		// TODO Auto-generated method stub
		return null;
	}
}
