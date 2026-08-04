typedef int (*iv_handler)(int,int,int); typedef void (*iv_keyboardhandler)(char*); typedef struct ifont_s ifont; typedef struct ibitmap_s ibitmap;
void InkViewMain(iv_handler h){} void CloseApp(void){} int ScreenWidth(void){return 758;} int ScreenHeight(void){return 1024;}
void SetPanelType(int x){} int DrawPanel(const ibitmap*a,const char*b,const char*c,int d){return 0;} void SetOrientation(int x){} void ClearScreen(void){} void DrawLine(int a,int b,int c,int d,int e){}
void DrawRect(int a,int b,int c,int d,int e){} void FillArea(int a,int b,int c,int d,int e){}
ifont *OpenFont(const char*a,int b,int c){return (ifont*)0;} void CloseFont(ifont*f){} void SetFont(ifont*f,int c){}
char *DrawTextRect(int a,int b,int c,int d,const char*s,int f){return (char*)0;} void FullUpdate(void){} void PartialUpdate(int a,int b,int c,int d){}
void OpenKeyboard(const char*a,char*b,int c,int d,iv_keyboardhandler h){} void Message(int a,const char*b,const char*c,int d){}
void ShowHourglass(void){} void HideHourglass(void){}

int NetConnect(const char *name){return 0;}
typedef void (*iv_timerproc)(void);
typedef struct iv_netinfo_s { int connected; char name[64]; char device[64]; char security[64]; char prefix[64]; int index; int atime; int speed; int reserved_0e; unsigned long bytes_in; unsigned long bytes_out; unsigned long packets_in; unsigned long packets_out; } iv_netinfo;
void SetHardTimer(const char *name, iv_timerproc tp, int ms){} void ClearTimerByName(const char *name){}
