# สัญญาอนุญาต

Hayabusa และกฎการตรวจจับของมันถูกเผยแพร่ภายใต้สัญญาอนุญาตที่แตกต่างกันสองแบบ

## Hayabusa (ตัวเครื่องมือ)

Hayabusa ถูกเผยแพร่ภายใต้ **[GNU Affero General Public License v3.0 (AGPLv3)](https://www.gnu.org/licenses/agpl-3.0.en.html)**
ข้อความทางกฎหมายฉบับเต็มอยู่ในไฟล์ [`LICENSE.txt`](https://github.com/Yamato-Security/hayabusa/blob/main/LICENSE.txt) ของที่เก็บข้อมูล (repository)

## กฎการตรวจจับ

กฎ [Sigma](https://github.com/SigmaHQ/sigma) และกฎการตรวจจับของ Hayabusa
(ซึ่งโฮสต์อยู่ในที่เก็บข้อมูล [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules))
ถูกเผยแพร่ภายใต้ **[Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md)**

## AGPL มีความหมายอย่างไรต่อคุณ

โดยสรุปแล้ว **คุณมีอิสระที่จะใช้ Hayabusa ได้ตามที่คุณต้องการ — รวมถึงเพื่อวัตถุประสงค์ทางการค้าด้วย**:
ภายในองค์กรของคุณ ในโซลูชัน SaaS สำหรับงานที่ปรึกษา การปฏิบัติงานตอบสนองต่อเหตุการณ์ (incident response)
และอื่น ๆ

AGPL เพิ่มเงื่อนไขสำคัญหนึ่งข้อ: **หากคุณแก้ไขหรือปรับปรุงโค้ดของ Hayabusa และมอบให้
ผู้อื่นในรูปแบบบริการ** (ตัวอย่างเช่น เป็นส่วนหนึ่งของบริการแบบ SaaS) **เราขอให้คุณเปิดเผยซอร์สโค้ด
ของการปรับปรุงเหล่านั้น** และทำให้สามารถใช้งานได้ภายใต้สัญญาอนุญาตเดียวกัน

เมื่อคุณทำการปรับปรุง เราจะรู้สึกซาบซึ้งเป็นอย่างยิ่งหากคุณจะ **ตอบแทนโครงการ**
ด้วยการ [ส่ง pull request](https://github.com/Yamato-Security/hayabusa/pulls) ไปยังที่เก็บข้อมูลต้นทาง (upstream)
— ด้วยวิธีนี้ ชุมชนทั้งหมดจะได้รับประโยชน์จากงานของคุณ

!!! note "ข้อมูลอื่น ๆ"
    Hayabusa ยังใช้ข้อมูล GeoLite2 ที่สร้างขึ้นโดย [MaxMind](https://www.maxmind.com) ด้วย
