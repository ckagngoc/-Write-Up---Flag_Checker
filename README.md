# [Write-Up] Flag_Checker

## Đề cho như sau:

![Imgur](https://i.imgur.com/s9uBvtP.png)

## Tiến hành

Cho file vào Detect It Easy ta được các thông tin như sau: 

![Imgur](https://i.imgur.com/u2WGKQj.png)

*Packer: UPX*
*Compiler:AutoIT*
*PE_32*

Đầu tiên dùng tool của UPX unpack file 

![Imgur](https://i.imgur.com/HgrbgTC.png)

Sau đó dùng UnautoIT để convert về source file AutoIT 

![Imgur](https://i.imgur.com/Yh4iWv4.png)

Khi chạy thấy chương trình xuất xâu "Incorrect !" Ctrl + F để tìm ta thấy được hàm checker() load một nùi opcode vào để load thành shellcode và check pass ta nhập vào như trên. 
Sau khi chuyển đống opcode vào các param hàm gọi DllCall với param là các string chỉ thị "user32.dll" gọi hàm "CallWindowProcA", và các var chứa shellcode và input: 

![Imgur](https://i.imgur.com/nIAJZEp.png)

Ý tưởng là ta sẽ đặt breakpoint vào hàm *CallWindowProcA* để khi chương trình load các tham số ta sẽ đọc được shellcode bằng IDA. Nhưng khi debug chưa kịp đến chỗ nhập input thì nhận
được msgBox sau:

![Imgur](https://i.imgur.com/FBR5ZEJ.png)

Xem xét các hàm được gọi trong main ta tìm được hàm antiDebug *IsDebuggerPresent*

![Imgur](https://i.imgur.com/Qlu4WbM.png)

Đặt breakpoint tại câu lệnh nhảy để bypass ta tiến hành debug lại chương trình, khi đến BP sửa cờ ZF để bypass.
Lúc này trong Modules view ta thấy chương trình đã load *User32.dll* ta tiến hành tìm và đặt BP trong hàm *CallWindowProcA* dể debug với pass bất kỳ

![Imgur](https://i.imgur.com/NiFdPGq.png)

Lúc này ta trace qua các param để tìm shellcode. Và sử dụng MakeData để xem xét các param, kết quả được như sau: 

![Imgur](https://i.imgur.com/GfL9xXy.png)

![Imgur](https://i.imgur.com/NLKQV2s.png)

Kiểm tra lại trong source AutoIT ta thấy đây chính là đoạn shellcode cần tìm. Vì shellcode là đoạn mã độc lập, thao tác với các param của chương trình qua địa chỉ và sử dụng
các hàm API qua *GetProcAddress*, hàm này sử dụng các string để truy xuất đến các dll nên khi MakeCode trong IDA ta sẽ để ý các đoạn byte là các string liên tục sẽ không được 
make. Tiến hành từ đầu shellcode ta thấy trong hexview có đoạn string liên tục là "user32.dll"

![Imgur](https://i.imgur.com/VAk4LUA.png)

Tiến hành debug vào shellcode ta xem xét các hàm con của hàm trên. Hai hàm đầu là hai hàm load lib của kernel32.dll và các hàm crytoAPI để mã hóa, hàm con cuối cùng là 
messageBoxA nên tiến hành đổi tên chúng cho tiện theo dõi.

![Imgur](https://i.imgur.com/hOkrVlp.png)





