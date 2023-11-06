//код с drag and drop
function allowDrop(event) {
    event.preventDefault();
}
function drag(event) {
    event.dataTransfer.setData("text", event.target.id);
}
function drop(event) {
    event.preventDefault();
    const data = event.dataTransfer.getData("text");
    if(data === "cpu1"){
        cpu1()
    }
    else if(data === "cpu2"){
        cpu2();
    }
    else if(data === "cpu3"){
        cpu3();
    }
    else if(data === "mother1"){
        mother1();
    }
    else if(data === "mother2"){
        mother2();
    }
    else if(data === "mother3"){
        mother3();
    }
    else if(data === "mother4"){
        mother4();
    }
    else if(data === "ram1"){
        ram1();
    }
    else if(data === "ram2"){
        ram2();
    }
    else if(data === "ram3"){
        ram3();
    }
    else if(data === "gpu1"){
        gpu1();
    }
    else if(data === "gpu2"){
        gpu2();
    }
    else if(data === "gpu3"){
        gpu3();
    }
    else if(data === "pu1"){
        pu1();
    }
    else if(data === "pu2"){
        pu2();
    }
    else if(data === "pu3"){
        pu3();
    }
    else if(data === "hdd1"){
        hdd1();
    }
    else if(data === "hdd2"){
        hdd2();
    }
    else if(data === "hdd3"){
        hdd3();
    }
    else if(data === "ssd1"){
        ssd1();
    }
    else if(data === "ssd2"){
        ssd2();
    }
    else if(data === "ssd3"){
        ssd3();
    }
    else if(data === "case1"){
        case1();
    }
    else if(data === "case2"){
        case2();
    }
    else if(data === "case3"){
        case3();
    }
    refresh();
}
//код с объектом PC
let nc = "not chosen";
let PC = {
    cpu: nc,
    mother: nc,
    ramType: nc,
    ram: nc,
    gpu: nc,
    hdd: nc,
    ssd: nc,
    power: 0,
    case: nc,
    socket: nc,
    minPower: 0
}
function refresh() {
    document.getElementById("cpu").innerHTML = PC.cpu;
    document.getElementById("mother").innerHTML = PC.mother;
    document.getElementById("ramType").innerHTML = PC.ramType;
    document.getElementById("ram").innerHTML = PC.ram;
    document.getElementById("gpu").innerHTML = PC.gpu;
    document.getElementById("hdd").innerHTML = PC.hdd;
    document.getElementById("ssd").innerHTML = PC.ssd;
    document.getElementById("power").innerHTML = PC.power + "Вт";
    document.getElementById("case").innerHTML = PC.case;
}
function reset(){
    PC.cpu = nc;
    PC.mother = nc;
    PC.ramType = nc;
    PC.ram = nc;
    PC.gpu = nc;
    PC.hdd = nc;
    PC.ssd = nc;
    PC.power = 0;
    PC.case = nc;
    PC.socket = nc;
    PC.minPower = 0;
    refresh();
}
function cpu1() {
    if(PC.socket === nc){
        PC.socket = "LGA1700";
        PC.cpu = "Intel Core i5-13600k";
        PC.ramType = "DDR5";
    }
    else if(PC.socket === "LGA1700"){
        PC.cpu = "Intel Core i5-13600k";
        PC.ramType = "DDR5";
    }
    else{
        alert("You can't choose this CPU, because of wrong socket!")
    }
}
function cpu2() {
    if(PC.socket === nc){
        PC.socket = "LGA1700";
        PC.cpu = "Intel Core i5-13400F";
        PC.ramType = "DDR5";
    }
    else if(PC.socket === "LGA1700"){
        PC.cpu = "Intel Core i5-13400F";
        PC.ramType = "DDR5";
    }
    else{
        alert("You can't choose this CPU, because of wrong socket!")
    }
}
function cpu3(){
    if(PC.socket === nc){
        PC.socket = "AM5";
        PC.cpu = "AMD Ryzen 7 7700X";
        PC.ramType = "DDR5";
    }
    else if(PC.socket === "AM5"){
        PC.cpu = "AMD Ryzen 7 7700X";
        PC.ramType = "DDR5";
    }
    else{
        alert("You can't choose this CPU, because of wrong socket!")
    }
}
function mother1(){
    if(PC.socket === nc){
        PC.socket = "LGA1700";
        PC.mother = "Gigabyte Z790 AORUS ELITE AX";
        PC.ramType = "DDR5";
    }
    else if(PC.socket === "LGA1700"){
        PC.mother = "Gigabyte Z790 AORUS ELITE AX";
        PC.ramType = "DDR5";
    }
    else{
        alert("You can't choose this Motherboard, because of wrong socket!")
    }
}
function mother2(){
    if(PC.socket === nc){
        PC.socket = "LGA1700";
        PC.mother = "MSI MPG Z790 Carbon WiFi";
        PC.ramType = "DDR5";
    }
    else if(PC.socket === "LGA1700"){
        PC.mother = "MSI MPG Z790 Carbon WiFi";
        PC.ramType = "DDR5";
    }
    else{
        alert("You can't choose this Motherboard, because of wrong socket!")
    }
}
function mother3(){
    if(PC.socket === nc){
        PC.socket = "LGA1700";
        PC.mother = "ASUS TUF Gaming Z790-Plus WiFi D4";
        PC.ramType = "DDR5";
    }
    else if(PC.socket === "LGA1700"){
        PC.mother = "ASUS TUF Gaming Z790-Plus WiFi D4";
        PC.ramType = "DDR5";
    }
    else{
        alert("You can't choose this Motherboard, because of wrong socket!")
    }
}
function mother4(){
    if(PC.socket === nc){
        PC.socket = "AM5";
        PC.mother = "ASUS ROG Strix B650E-F Gaming WiFi";
        PC.ramType = "DDR5";
    }
    else if(PC.socket === "AM5"){
        PC.mother = "ASUS ROG Strix B650E-F Gaming WiFi";
        PC.ramType = "DDR5";
    }
    else{
        alert("You can't choose this Motherboard, because of wrong socket!")
    }
}
function mother5(){
    if(PC.socket === nc){
        PC.socket = "AM5";
        PC.mother = "Gigabyte X670 AORUS Elite AX";
        PC.ramType = "DDR5";
    }
    else if(PC.socket === "AM5"){
        PC.mother = "Gigabyte X670 AORUS Elite AX";
        PC.ramType = "DDR5";
    }
    else{
        alert("You can't choose this Motherboard, because of wrong socket!")
    }
}
function ram1(){
    PC.ram = "16 GB";
}
function ram2(){
    PC.ram = "32 GB";
}
function ram3(){
    PC.ram = "64 GB";
}
function gpu1(){
    PC.minPower = 850;
    if(PC.power < PC.minPower){
        PC.minPower = 0;
        alert("Choose better power unit first!");
    }
    else{
        PC.gpu = "NVIDIA RTX 4090";
    }
}
function gpu2(){
    PC.minPower = 550;
    if(PC.power < PC.minPower){
        PC.minPower = 0;
        alert("Choose better power unit first!");
    }
    else{
        PC.gpu = "NVIDIA RTX 4060";
    }
}
function gpu3(){
    PC.minPower = 750;
    if(PC.power < PC.minPower){
        PC.minPower = 0;
        alert("Choose better power unit first!");
    }
    else{
        PC.gpu = "AMD Radeon RX 7900";
    }
}
function pu1(){
    PC.power = 550;
    if(PC.power < PC.minPower){
        PC.power = 0;
        alert("Choose better power unit!");
    }
}
function pu2(){
    PC.power = 750;
    if(PC.power < PC.minPower){
        PC.power = 0;
        alert("Choose better power unit!");
    }
}
function pu3(){
    PC.power = 1000;
    if(PC.power < PC.minPower){
        PC.power = 0;
        alert("Choose better power unit!");
    }
}
function hdd1(){
    PC.hdd = "1TB";
}
function hdd2(){
    PC.hdd = "2TB";
}
function hdd3(){
    PC.hdd = "5TB";
}
function ssd1(){
    PC.ssd = "256GB";
}
function ssd2(){
    PC.ssd = "512GB";
}
function ssd3(){
    PC.ssd = "1TB";
}
function case1(){
    PC.case = "Powercase Mistral X4 Mesh LED Black";
}
function case2(){
    PC.case = "NZXT H510 Elite Black TG";
}
function case3(){
    PC.case = "DeepCool MATREXX 55 MESH Black";
}
document.getElementById("cpu").innerHTML = PC.cpu;
document.getElementById("mother").innerHTML = PC.mother;
document.getElementById("ramType").innerHTML = PC.ramType;
document.getElementById("ram").innerHTML = PC.ram;
document.getElementById("gpu").innerHTML = PC.gpu;
document.getElementById("hdd").innerHTML = PC.hdd;
document.getElementById("ssd").innerHTML = PC.ssd;
document.getElementById("power").innerHTML = PC.power + "Вт";
document.getElementById("case").innerHTML = PC.case;