import { log } from '../log.js';
import logoImg from '../assets/logo.png';

export default function Header() {
  log('<Header /> rendered', 1);

  return (
    <header id="main-header">
      <img src={logoImg} alt="Magnifying glass" />
      <h1>Advanced Counter</h1>
    </header>
  );
}
