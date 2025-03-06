let index = 0;
function moveSlide(step) {
    const slides = document.querySelectorAll(".slide");
    index = (index + step + slides.length) % slides.length;
    document.querySelector(".slider").style.transform = `translateX(-${index * 100}%)`;
}