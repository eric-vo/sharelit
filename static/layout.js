document.addEventListener('DOMContentLoaded', () => {
    const statusMessage = document.querySelector('#status-message');
    const furtherDown = document.querySelector('.further-down');

    if (furtherDown) {
        const statusMessageHeight = statusMessage.offsetHeight;
        const furtherDownMarginTop = window.getComputedStyle(furtherDown).marginTop;

        /*
        Subtract the height of the status message from margin-top of .further-down
        so that the .further-down element isn't shifted down
        when the status message is displayed
        */
        furtherDown.style.marginTop = `calc(${furtherDownMarginTop} - ${statusMessageHeight}px)`;
    }
});
