//----------------------------------------------------------------
// Project              : Network Scanner
// Author               : Hanteville Nicolas
// Licence              : GPLv3
//----------------------------------------------------------------
#include "../resources.h"
//----------------------------------------------------------------
#define IOC_LINE_MAX_SZ     8192
//----------------------------------------------------------------
/*
$;

MD5;d6aa97d33d459ea3670056e737c99a3d;N;;										=> hash
SIGN;signatur de test;N;;														        => sign of binnary files
SIZE;Type;10;100;											    				          => size min, max en bytes !!!
FILE;Type;chaine dans le nom;Obligatoire/bloquant ou non;		=> search in file name/ext
DATA;Type;"chaine à chercher";Obligatoire/bloquant ou non;	=> search in the files data
DESC;"description";"description2/source/author";;						=> description
*/
//----------------------------------------------------------------
char *GetTParams(char *line, char separator, unsigned int header_bypass, char *param1, char *param2, char *param3, char *param4)
{
  char *s = (line+header_bypass);
  char buffer[IOC_LINE_MAX_SZ]="";
  char *d = buffer;

  param1[0] = 0;
  param2[0] = 0;
  param3[0] = 0;
  param4[0] = 0;

  //p1
  while(*s && (*s != separator))*d++ = *s++;
  *d = 0;
  if (buffer[0] == '"')
  {
    d--;
    *d = 0;
  }
  snprintf(param1,IOC_LINE_MAX_SZ,"%s",buffer+1);
  d = buffer;
  *d = 0;

  while(*s && (*s != separator))*d++ = *s++;
  *d = 0;
  if (buffer[0] == '"')
  {
    d--;
    *d = 0;
  }
  snprintf(param2,IOC_LINE_MAX_SZ,"%s",buffer+1);
  d = buffer;
  *d = 0;

  while(*s && (*s != separator))*d++ = *s++;
  *d = 0;
  if (buffer[0] == '"')
  {
    d--;
    *d = 0;
  }
  snprintf(param3,IOC_LINE_MAX_SZ,"%s",buffer+1);
  d = buffer;
  *d = 0;

  while(*s && (*s != separator))*d++ = *s++;
  *d = 0;
  if (buffer[0] == '"')
  {
    d--;
    *d = 0;
  }
  snprintf(param4,IOC_LINE_MAX_SZ,"%s",buffer+1);

  return ++d;
}
//----------------------------------------------------------------
BOOL MakeIOC(char *file, SIOC*ioc)
{
  //get file to CSV format and make database !
  BOOL ret = FALSE;
  char *s, buffer[IOC_LINE_MAX_SZ];//max buffer size
  char param1[IOC_LINE_MAX_SZ], param2[IOC_LINE_MAX_SZ], param3[IOC_LINE_MAX_SZ], param4[IOC_LINE_MAX_SZ];

  //init SIOC*ioc
  ioc->nb_ioc     = 0;      //real number
  ioc->nb_ioc_mem = 10;     //allready allocated
  ioc->lioc       = malloc((sizeof(S_IOC)+1)*ioc->nb_ioc_mem);

  char path[LINE_SIZE]="";
  strncat(GetLocalPath(path, LINE_SIZE),file,LINE_SIZE); //add local path + \file

  //open ref file
  HANDLE hfile = CreateFile(path,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,0);
  if (hfile != INVALID_HANDLE_VALUE)
  {
    DWORD read =0, filesz = 0;
    filesz = GetFileSize(hfile,NULL);
    if (filesz > 0 && filesz< 0xFFFFFFFF)
    {
      //load all the file in memory
      char *datas = (char*)LocalAlloc(LMEM_FIXED, sizeof(char)*filesz+1);
      if (datas != NULL)
      {
        if (ReadFile(hfile, datas, filesz, &read, 0))
        {
          if (datas[0] != 0 && read == filesz)
          {
            //load by line !
            datas[filesz] = 0;
            char *s = datas, *d = buffer;
            while (*s)
            {
              buffer[0] = 0;
              d         = buffer;
              while(*s && (*s != '\r') && (*s != '\n'))*d++ = *s++;
              while(*s && ((*s == '\n') || (*s == '\r')))s++;
              *d = 0;

              if (buffer[0] != 0 && buffer[0] != '#')
              {
                if (buffer[0] == '$' && buffer[1] == ';') //ok start with $;
                {
                  //all the datas are on 3 by 3
                  s = buffer+2; //pass $;
                  while (s = GetTParams(s, ';', 0, param1, param2, param3, param4))
                  {
                    if (strlen(param1) < 3)continue; //3 or 4 min

                    switch(param1[2])
                    {
                      case '5'://MD5
                      {
                        if (ioc->lioc[ioc->nb_ioc].nb_hash < MAX_ITEM_BY_IOC)
                        {
                          ioc->lioc[ioc->nb_ioc].hash[ioc->lioc[ioc->nb_ioc].nb_hash].type = HASH_TYPE_MD5;
                          snprintf(ioc->lioc[ioc->nb_ioc].hash[ioc->lioc[ioc->nb_ioc].nb_hash].hash,HASH_MAX_SIZE,"%s",param2);

                          if (param3[0] == 'n' || param3[0] == 'N') ioc->lioc[ioc->nb_ioc].hash[ioc->lioc[ioc->nb_ioc].nb_hash].mandatory = FALSE;
                          else ioc->lioc[ioc->nb_ioc].hash[ioc->lioc[ioc->nb_ioc].nb_hash].mandatory = TRUE;

                          ioc->lioc[ioc->nb_ioc].nb_hash++;
                        }else AddMsg(h_main, (char*)"ERROR",(char*)"Too Much MD5/SHA in loading IOC file",file,FALSE);
                      }
                      break;
                      case 'a'://SHA
                      case 'A':
                      {
                        if (ioc->lioc[ioc->nb_ioc].nb_hash < MAX_ITEM_BY_IOC)
                        {
                          if (param1[3] == '1')ioc->lioc[ioc->nb_ioc].hash[ioc->lioc[ioc->nb_ioc].nb_hash].type = HASH_TYPE_SHA1;
                          else ioc->lioc[ioc->nb_ioc].hash[ioc->lioc[ioc->nb_ioc].nb_hash].type = HASH_TYPE_SHA256;

                          snprintf(ioc->lioc[ioc->nb_ioc].hash[ioc->lioc[ioc->nb_ioc].nb_hash].hash,HASH_MAX_SIZE,"%s",param2);

                          if (param3[0] == 'n' || param3[0] == 'N') ioc->lioc[ioc->nb_ioc].hash[ioc->lioc[ioc->nb_ioc].nb_hash].mandatory = FALSE;
                          else ioc->lioc[ioc->nb_ioc].hash[ioc->lioc[ioc->nb_ioc].nb_hash].mandatory = TRUE;

                          ioc->lioc[ioc->nb_ioc].nb_hash++;
                        }else AddMsg(h_main, (char*)"ERROR",(char*)"Too Much MD5/SHA in loading IOC file",file,FALSE);
                      }
                      break;
                      case 'g'://SIGN
                      case 'G':
                      {
                        if (ioc->lioc[ioc->nb_ioc].nb_sign < MAX_ITEM_BY_IOC)
                        {
                          snprintf(ioc->lioc[ioc->nb_ioc].sign[ioc->lioc[ioc->nb_ioc].nb_sign].sign,SFSIGN_MAX_SZ,"%s",param2);

                          if (param3[0] == 'n' || param3[0] == 'N') ioc->lioc[ioc->nb_ioc].sign[ioc->lioc[ioc->nb_ioc].nb_sign].mandatory = FALSE;
                          else ioc->lioc[ioc->nb_ioc].sign[ioc->lioc[ioc->nb_ioc].nb_sign].mandatory = TRUE;

                          ioc->lioc[ioc->nb_ioc].nb_sign++;
                        }else AddMsg(h_main, (char*)"ERROR",(char*)"Too Much SIGN in loading IOC file",file,FALSE);
                      }
                      break;
                      case 'z'://SIZE
                      case 'Z':
                      {
                        if (ioc->lioc[ioc->nb_ioc].nb_size < MAX_ITEM_BY_IOC)
                        {
                          ioc->lioc[ioc->nb_ioc].size[ioc->lioc[ioc->nb_ioc].nb_size].type = atol(param2);

                          ioc->lioc[ioc->nb_ioc].size[ioc->lioc[ioc->nb_ioc].nb_size].file_size   = atoll(param3);
                          if (param4[0] != 0) ioc->lioc[ioc->nb_ioc].size[ioc->lioc[ioc->nb_ioc].nb_size].file_size2 = atoll(param4);
                          else ioc->lioc[ioc->nb_ioc].size[ioc->lioc[ioc->nb_ioc].nb_size].file_size2 = 0;

                          ioc->lioc[ioc->nb_ioc].nb_size++;
                        }else AddMsg(h_main, (char*)"ERROR",(char*)"Too Much SIZE in loading IOC file",file,FALSE);
                      }
                      break;
                      case 'l'://FILE
                      case 'L':
                      {
                        if (ioc->lioc[ioc->nb_ioc].nb_files < MAX_ITEM_BY_IOC)
                        {
                          ioc->lioc[ioc->nb_ioc].files[ioc->lioc[ioc->nb_ioc].nb_files].type = atol(param2);

                          if (param3[0] != 0)snprintf(ioc->lioc[ioc->nb_ioc].files[ioc->lioc[ioc->nb_ioc].nb_files].file,FILES_ST_MAX_SIZE,"%s",param3);
                          else continue;

                          if (param4[0] == 'n' || param4[0] == 'N') ioc->lioc[ioc->nb_ioc].files[ioc->lioc[ioc->nb_ioc].nb_files].mandatory = FALSE;
                          else ioc->lioc[ioc->nb_ioc].files[ioc->lioc[ioc->nb_ioc].nb_files].mandatory = TRUE;

                          ioc->lioc[ioc->nb_ioc].nb_files++;
                        }else AddMsg(h_main, (char*)"ERROR",(char*)"Too Much FILES in loading IOC file",file,FALSE);
                      }
                      break;
                      case 't'://DATA
                      case 'T':
                      {
                        if (ioc->lioc[ioc->nb_ioc].nb_datas < MAX_ITEM_BY_IOC)
                        {
                          ioc->lioc[ioc->nb_ioc].datas[ioc->lioc[ioc->nb_ioc].nb_datas].type = atol(param2);

                          if (param3[0] != 0)snprintf(ioc->lioc[ioc->nb_ioc].datas[ioc->lioc[ioc->nb_ioc].nb_datas].datas,DATAS_MAX_SIZE,"%s",param3);
                          else continue;

                          if (param4[0] == 'n' || param4[0] == 'N') ioc->lioc[ioc->nb_ioc].datas[ioc->lioc[ioc->nb_ioc].nb_datas].mandatory = FALSE;
                          else ioc->lioc[ioc->nb_ioc].datas[ioc->lioc[ioc->nb_ioc].nb_datas].mandatory = TRUE;

                          ioc->lioc[ioc->nb_ioc].nb_datas++;
                        }else AddMsg(h_main, (char*)"ERROR",(char*)"Too Much DATAS in loading IOC file",file,FALSE);
                      }
                      break;
                      case 'd'://DESC
                      case 'D':
                      {
                        if (param2[0] != 0)snprintf(ioc->lioc[ioc->nb_ioc].infos1,IOC_INFO_MAX_SZ,"%s",param2);
                        else ioc->lioc[ioc->nb_ioc].infos1[0] = 0;
                        if (param3[0] != 0)snprintf(ioc->lioc[ioc->nb_ioc].infos2,IOC_INFO_MAX_SZ,"%s",param3);
                        else ioc->lioc[ioc->nb_ioc].infos2[0] = 0;
                        if (param4[0] != 0)snprintf(ioc->lioc[ioc->nb_ioc].infos3,IOC_INFO_MAX_SZ,"%s",param4);
                        else ioc->lioc[ioc->nb_ioc].infos3[0] = 0;
                      }
                      break;
                    }
                    ret = TRUE;
                  }

                  ioc->nb_ioc++;
                  if (ioc->nb_ioc >= ioc->nb_ioc_mem)
                  {
                    ioc->nb_ioc_mem = ioc->nb_ioc_mem +10;
                    ioc->lioc       = realloc(ioc->lioc, ioc->nb_ioc_mem);
                    if (ioc->lioc == NULL)
                    {
                      FreeIOC(ioc);
                      LocalFree(datas);
                      CloseHandle(hfile);
                      return ret;
                    }
                  }
                }
              }
            }
          }else if (read != filesz)AddMsg(h_main, (char*)"ERROR",(char*)"In loading IOC file",file,FALSE);
        }
        LocalFree(datas);
      }
    }
    CloseHandle(hfile);
  }
  return ret;
}
//----------------------------------------------------------------
void FreeIOC(SIOC*ioc)
{
  unsigned int i =0;
  for (i; i< ioc->nb_ioc_mem;i++)
  {
    /*if (ioc->lioc[i].files != NULL) free(ioc->lioc[i].files);
    if (ioc->lioc[i].hash != NULL)  free(ioc->lioc[i].hash);
    if (ioc->lioc[i].size != NULL)  free(ioc->lioc[i].size);
    if (ioc->lioc[i].sign != NULL)  free(ioc->lioc[i].sign);
    if (ioc->lioc[i].datas != NULL) free(ioc->lioc[i].datas);*/
    free((void*)(&(ioc->lioc[i])));
  }
}
//----------------------------------------------------------------
int CheckFileIOC(DWORD iitem, char *file, long long int filesize, WIN32_FIND_DATA *data, SIOC*ioc)
{
  int i, i, ret = -1;//by default no check done

  BOOL bsize, bfile, bsign, bdata, bhash;
  HANDLE hfile;

  for (i=0; i< ioc->nb_ioc; i++)
  {
    //init
    bsize = FALSE;
    bhash = FALSE;
    bsign = FALSE;
    bfile = FALSE;
    bdata = FALSE;

    //check for each IOC all datas !
    //[SIZE]
    for (j=0; j< ioc->lioc[i].nb_size && scan_start; j++)
    {
      if (ioc->lioc[i].size[j].type == FSIZE_TYPE_EQ)
      {
        if (ioc->lioc[i].size[j].file_size == filesize)
        {
          bsize = TRUE;
          break;
        }
      }else if (ioc->lioc[i].size[j].type == FSIZE_TYPE_MIN)
      {
        if (ioc->lioc[i].size[j].file_size <= filesize)
        {
          bsize = TRUE;
          break;
        }
      }else if (ioc->lioc[i].size[j].type == FSIZE_TYPE_MAX)
      {
        if (ioc->lioc[i].size[j].file_size >= filesize)
        {
          bsize = TRUE;
          break;
        }
      }else if (ioc->lioc[i].size[j].type == FSIZE_TYPE_MINMAX)
      {
        if (ioc->lioc[i].size[j].file_size >= filesize && ioc->lioc[i].size[j].file_size <= filesize)
        {
          bsize = TRUE;
          break;
        }
      }
    }

    //[SIGN] //Disable for moment !!
    //https://msdn.microsoft.com/en-us/library/windows/desktop/aa382378%28v=vs.85%29.aspx

    if (ioc->lioc[i].nb_hash || ioc->lioc[i].nb_datas || ioc->lioc[i].nb_files)
    {
      hfile = CreateFile(file, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0);
      if (hfile != INVALID_HANDLE_VALUE)
      {
        //[HASH]
        BOOL  bmd5    = FALSE,
              bsha1   = FALSE,
              bsha256 = FALSE;
        for (j=0; j< ioc->lioc[i].nb_hash && scan_start; j++)
        {
          if (ioc->lioc[i].hash[j].type == HASH_TYPE_MD5)     bmd5    = TRUE;
          if (ioc->lioc[i].hash[j].type == HASH_TYPE_SHA1)    bsha1   = TRUE;
          if (ioc->lioc[i].hash[j].type == HASH_TYPE_SHA256)  bsha256 = TRUE;
        }

        char s_sha256[SHA256_SIZE]  = "",
             s_sha1[SHA1_SIZE]      = "",
             s_md5[MD5_SIZE]        = "";

        if (bmd5 || bsha1 || bsha256)
        {
          if (bmd5)     FileToMd5(hfile, s_md5);
          if (s_sha1)   FileToSHA1(hfile, s_md5);
          if (s_sha256) FileToSHA256(hfile, s_md5);

          for (j=0; j< ioc->lioc[i].nb_hash && scan_start; j++)
          {
            if (ioc->lioc[i].hash[j].type == HASH_TYPE_MD5)            {
              if (compare_nocas(s_md5,    ioc->lioc[i].hash[j].hash)){bhash = TRUE;break;}
            }
            if (ioc->lioc[i].hash[j].type == HASH_TYPE_SHA1)            {
              if (compare_nocas(s_sha1,   ioc->lioc[i].hash[j].hash)){bhash = TRUE;break;}
            }
            if (ioc->lioc[i].hash[j].type == HASH_TYPE_SHA256)            {
              if (compare_nocas(s_sha256, ioc->lioc[i].hash[j].hash)){bhash = TRUE;break;}
            }
          }
        }

        //[FILE]

        //[DATA]

        CloseHandle(hfile);
      }

      //check if ok or not !!!


    }
  }
  return ret;//if IOC exist : 1 or 0, -1 if error
}
